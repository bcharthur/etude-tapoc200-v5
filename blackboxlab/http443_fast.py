from __future__ import annotations

import json
import socket
import ssl
import time


def post_json(target_ip: str, path: str, obj: dict, timeout: float = 3.0) -> dict:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Accept: application/json\r\n"
        "User-Agent: tapolab-blackbox/0.3\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
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

    try:
        with socket.create_connection((target_ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None) as s:
                result["tls_version"] = s.version()
                s.sendall(request)

                data = bytearray()

                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    data.extend(chunk)

                head, sep, rest = bytes(data).partition(b"\r\n\r\n")
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

                content_length = None
                try:
                    values = headers.get("content-length") or []
                    if values:
                        content_length = int(values[-1])
                except ValueError:
                    pass

                body_buf = bytearray(rest)

                if content_length is not None:
                    while len(body_buf) < content_length:
                        chunk = s.recv(min(8192, content_length - len(body_buf)))
                        if not chunk:
                            break
                        body_buf.extend(chunk)
                    body_raw = bytes(body_buf[:content_length])
                else:
                    while len(body_buf) < 131072:
                        try:
                            chunk = s.recv(8192)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        body_buf.extend(chunk)
                    body_raw = bytes(body_buf)

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
