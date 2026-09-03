from __future__ import annotations

import re
import socket
import time
from collections import Counter


PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^,\s]+)')


def _parse_digest(value: str) -> dict:
    if not value.lower().startswith("digest "):
        return {"scheme": None, "params": {}, "raw": value}

    params = {}
    for match in PARAM_RE.finditer(value[7:]):
        key = match.group(1).lower()
        val = match.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        params[key] = val

    return {"scheme": "Digest", "params": params, "raw": value}


def _request(target_ip: str, method: str, path: str, timeout: float = 2.0) -> dict:
    body = b""
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {target_ip}:8800\r\n"
        "User-Agent: tapolab-blackbox/0.2\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    started = time.perf_counter()
    result = {
        "method": method,
        "path": path,
        "status_line": None,
        "headers": {},
        "auth_challenge": None,
        "body_preview": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 8800), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)

            data = bytearray()
            while len(data) < 65536:
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                if b"\r\n\r\n" in data:
                    break

        raw = bytes(data)
        head, _, body = raw.partition(b"\r\n\r\n")
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
        auths = headers.get("www-authenticate", [])
        if auths:
            result["auth_challenge"] = _parse_digest(auths[-1])
        result["body_preview"] = body[:2048].decode("utf-8", errors="replace") or None

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def stream_8800_route_matrix(target_ip: str, timeout: float = 2.0) -> dict:
    cases = [
        ("POST", "/stream"),
        ("POST", "/"),
        ("POST", "/app"),
        ("POST", "/stream/"),
        ("GET", "/stream"),
        ("HEAD", "/stream"),
        ("OPTIONS", "/stream"),
    ]

    results = [_request(target_ip, method, path, timeout) for method, path in cases]

    candidates = []
    for r in results:
        status = r.get("status_line") or ""
        if any(f" {code} " in status for code in range(200, 300)):
            # OPTIONS/HEAD may legitimately be informational; flag for review, not vuln.
            candidates.append({
                "method": r["method"],
                "path": r["path"],
                "status_line": status,
            })

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "results": results,
        "two_xx_without_auth": candidates,
    }


def stream_8800_nonce_profile(
    target_ip: str,
    count: int = 8,
    timeout: float = 2.0,
) -> dict:
    samples = []

    for _ in range(count):
        r = _request(target_ip, "POST", "/stream", timeout)
        challenge = r.get("auth_challenge") or {}
        params = challenge.get("params", {})

        samples.append({
            "status_line": r.get("status_line"),
            "nonce": params.get("nonce"),
            "opaque": params.get("opaque"),
            "realm": params.get("realm"),
            "algorithm": params.get("algorithm"),
            "qop": params.get("qop"),
            "encrypt_type": params.get("encrypt_type"),
            "x_preconn": (r.get("headers", {}).get("x-preconn") or [None])[-1],
            "x_hb": (r.get("headers", {}).get("x-hb") or [None])[-1],
            "elapsed_ms": r.get("elapsed_ms"),
        })

    nonces = [s["nonce"] for s in samples if s["nonce"]]
    opaques = [s["opaque"] for s in samples if s["opaque"]]

    return {
        "target_ip": target_ip,
        "sample_count": len(samples),
        "nonce_count": len(nonces),
        "unique_nonce_count": len(set(nonces)),
        "nonce_all_unique": bool(nonces) and len(nonces) == len(set(nonces)),
        "opaque_values": sorted(set(opaques)),
        "opaque_stable": bool(opaques) and len(set(opaques)) == 1,
        "samples": samples,
    }
