from __future__ import annotations

import json
import socket
import ssl
import time


def _call(target_ip: str, path: str, obj: dict, timeout: float = 3.0) -> dict:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "User-Agent: tapolab-blackbox/0.2\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
    result = {
        "path": path,
        "request_json": obj,
        "status_line": None,
        "headers": {},
        "body": None,
        "json": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None) as s:
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


def https_443_oracle_matrix(target_ip: str, timeout: float = 3.0) -> dict:
    discover = {
        "method": "login",
        "params": {"sub_method": "discover"},
    }

    unknown = {
        "method": "tapolab_unknown_method",
        "params": {},
    }

    empty_multi = {
        "method": "multipleRequest",
        "params": {"requests": []},
    }

    cases = [
        ("/", discover),
        ("/app", discover),
        ("/stream", discover),
        ("/", unknown),
        ("/app", unknown),
        ("/", empty_multi),
        ("/app", empty_multi),
    ]

    results = [_call(target_ip, path, obj, timeout) for path, obj in cases]

    signatures = []
    for r in results:
        obj = r.get("json")
        error_code = obj.get("error_code") if isinstance(obj, dict) else None
        signatures.append({
            "path": r["path"],
            "method": r["request_json"].get("method"),
            "status_line": r.get("status_line"),
            "error_code": error_code,
            "body_length": len(r.get("body") or ""),
        })

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "login_completed": False,
        "signatures": signatures,
        "results": results,
    }
