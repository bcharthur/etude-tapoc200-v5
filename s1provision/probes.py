from __future__ import annotations

import socket
import ssl
import json
import time


def tcp_probe(ip: str, port: int, timeout: float = 0.6) -> dict:
    started = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {
                "port": port,
                "open": True,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                "error": None,
            }
    except OSError as exc:
        return {
            "port": port,
            "open": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }


def https_discover(ip: str, timeout: float = 2.0) -> dict:
    body = b'{"method":"login","params":{"sub_method":"discover"}}'

    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "User-Agent: tapolab-s1/0.6\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "target_ip": ip,
        "tls_version": None,
        "status_line": None,
        "json": None,
        "error": None,
    }

    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
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

                head, _, rest = bytes(data).partition(b"\r\n\r\n")
                lines = head.decode("latin-1", errors="replace").splitlines()
                if lines:
                    result["status_line"] = lines[0]

                content_length = 0
                for line in lines[1:]:
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    if k.strip().lower() == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            pass

                body_buf = bytearray(rest)
                while content_length and len(body_buf) < content_length:
                    chunk = s.recv(min(8192, content_length - len(body_buf)))
                    if not chunk:
                        break
                    body_buf.extend(chunk)

                text = bytes(body_buf[:content_length] if content_length else body_buf).decode(
                    "utf-8", errors="replace"
                )

                try:
                    result["json"] = json.loads(text)
                except Exception:
                    result["body_preview"] = text[:2048]

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result
