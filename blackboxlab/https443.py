from __future__ import annotations

import json
import socket
import ssl
import time


def _https_post_json(
    target_ip: str,
    path: str,
    obj: dict,
    timeout: float = 3.0,
) -> dict:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "User-Agent: tapolab-blackbox/0.1\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    result = {
        "path": path,
        "request_json": obj,
        "tls_version": None,
        "status_line": None,
        "headers": {},
        "body": None,
        "json": None,
        "error": None,
        "elapsed_ms": None,
    }

    started = time.perf_counter()

    try:
        with socket.create_connection((target_ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=None) as s:
                result["tls_version"] = s.version()
                s.sendall(request)

                data = bytearray()
                while len(data) < 131072:
                    try:
                        chunk = s.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data.extend(chunk)

        raw_resp = bytes(data)
        head, _, body_raw = raw_resp.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", errors="replace").splitlines()

        if lines:
            result["status_line"] = lines[0]

        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), []).append(v.strip())
        result["headers"] = headers

        text = body_raw.decode("utf-8", errors="replace")
        result["body"] = text

        try:
            result["json"] = json.loads(text)
        except Exception:
            pass

    except (OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def https_443_preauth_discovery(target_ip: str, timeout: float = 3.0) -> dict:
    """
    Probe a modern Tapo pre-auth discovery shape reported by community clients.
    No username/password is supplied and no login completion is attempted.
    """
    candidates = [
        (
            "/",
            {
                "method": "login",
                "params": {"sub_method": "discover"},
            },
        ),
        (
            "/app",
            {
                "method": "login",
                "params": {"sub_method": "discover"},
            },
        ),
    ]

    results = [
        _https_post_json(target_ip, path, body, timeout)
        for path, body in candidates
    ]

    interesting = []
    for r in results:
        obj = r.get("json")
        if isinstance(obj, dict):
            # Extract only non-secret negotiation metadata.
            flat = json.dumps(obj).lower()
            if any(k in flat for k in (
                '"pake"',
                '"encrypt_type"',
                '"user_hash_type"',
                '"tls"',
                '"port"',
                '"nonce"',
                '"cnonce"',
            )):
                interesting.append(r["path"])

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "login_completed": False,
        "results": results,
        "negotiation_metadata_observed_on": interesting,
    }
