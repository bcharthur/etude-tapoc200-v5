from __future__ import annotations

import re
import socket
import time


AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^,\s]+)')


def _parse_auth_challenge(value: str) -> dict:
    parts = value.split(None, 1)
    scheme = parts[0] if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    params = {}
    for m in AUTH_PARAM_RE.finditer(rest):
        key = m.group(1).lower()
        val = m.group(2)
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        params[key] = val

    return {"scheme": scheme, "params": params, "raw": value}


def _rtsp_request(ip: str, request: bytes, port: int = 554, timeout: float = 2.0) -> dict:
    started = time.perf_counter()
    result = {
        "ip": ip,
        "port": port,
        "request": request.decode("ascii", errors="replace"),
        "response": None,
        "status_line": None,
        "headers": {},
        "header_lines": [],
        "auth_challenges": [],
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)

            chunks = []
            total = 0
            while total < 65536:
                try:
                    data = s.recv(8192)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if b"\r\n\r\n" in b"".join(chunks):
                    break

            raw = b"".join(chunks).decode("latin-1", errors="replace")
            result["response"] = raw
            lines = raw.splitlines()

            if lines:
                result["status_line"] = lines[0]

            headers = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                result["header_lines"].append({"name": key, "value": value})
                headers.setdefault(key, []).append(value)

                if key == "www-authenticate":
                    result["auth_challenges"].append(
                        _parse_auth_challenge(value)
                    )

            result["headers"] = headers

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def rtsp_options(ip: str, port: int = 554, timeout: float = 2.0) -> dict:
    request = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: tapolab/0.5\r\n"
        "\r\n"
    ).encode("ascii")
    return _rtsp_request(ip, request, port, timeout)


def rtsp_describe(ip: str, stream: str, port: int = 554, timeout: float = 2.0) -> dict:
    if stream not in {"stream1", "stream2"}:
        raise ValueError("stream doit être stream1 ou stream2")

    request = (
        f"DESCRIBE rtsp://{ip}:{port}/{stream} RTSP/1.0\r\n"
        "CSeq: 2\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: tapolab/0.5\r\n"
        "\r\n"
    ).encode("ascii")
    return _rtsp_request(ip, request, port, timeout)


def rtsp_baseline(ip: str, timeout: float = 2.0) -> dict:
    return {
        "options": rtsp_options(ip, timeout=timeout),
        "describe_stream1": rtsp_describe(ip, "stream1", timeout=timeout),
        "describe_stream2": rtsp_describe(ip, "stream2", timeout=timeout),
    }
