from __future__ import annotations

import json
import socket
import ssl
import time

from .scope import load_scope


PORTS = [80, 443, 554, 2020, 8800]


def tcp_probe(ip, port, timeout=0.5):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {
                "open": True,
                "port": port,
                "elapsed_ms": round((time.perf_counter()-t0)*1000, 2),
                "error": None,
            }
    except OSError as exc:
        return {
            "open": False,
            "port": port,
            "elapsed_ms": round((time.perf_counter()-t0)*1000, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }


def https_discover(ip, timeout=1.5):
    body = b'{"method":"login","params":{"sub_method":"discover"}}'
    req = (
        "POST / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    out = {"error": None, "status_line": None, "json": None}
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None) as s:
                s.sendall(req)
                data = bytearray()
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    c = s.recv(8192)
                    if not c:
                        break
                    data.extend(c)
                head, _, rest = bytes(data).partition(b"\r\n\r\n")
                lines = head.decode("latin-1", errors="replace").splitlines()
                if lines:
                    out["status_line"] = lines[0]
                length = None
                for line in lines[1:]:
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    if k.strip().lower() == "content-length":
                        try:
                            length = int(v.strip())
                        except Exception:
                            pass
                buf = bytearray(rest)
                while length is not None and len(buf) < length:
                    c = s.recv(min(8192, length-len(buf)))
                    if not c:
                        break
                    buf.extend(c)
                text = bytes(buf[:length] if length is not None else buf).decode(
                    "utf-8", errors="replace"
                )
                try:
                    out["json"] = json.loads(text)
                except Exception:
                    out["body_preview"] = text[:1024]
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def streamd_handshake(ip, timeout=1.5):
    req = (
        "POST /stream HTTP/1.1\r\n"
        f"Host: {ip}:8800\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    out = {
        "status_line": None,
        "headers": {},
        "error": None,
    }
    try:
        with socket.create_connection((ip, 8800), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 65536:
                c = s.recv(4096)
                if not c:
                    break
                data.extend(c)
            head = bytes(data).partition(b"\r\n\r\n")[0]
            lines = head.decode("latin-1", errors="replace").splitlines()
            if lines:
                out["status_line"] = lines[0]
            for line in lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                out["headers"].setdefault(k.strip().lower(), []).append(v.strip())
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def snapshot(ip: str | None = None):
    scope = load_scope()
    target = ip or scope.target_ip

    tcp = {str(p): tcp_probe(target, p) for p in PORTS}
    out = {
        "scope": {
            "target_ip": scope.target_ip,
            "target_mac": scope.target_mac,
            "scope_source": scope.source,
        },
        "observed_ip": target,
        "tcp": tcp,
        "https_discover": None,
        "streamd": None,
        "tdp_decrypt": None,
    }

    if tcp["443"]["open"]:
        out["https_discover"] = https_discover(target)

    if tcp["8800"]["open"]:
        out["streamd"] = streamd_handshake(target)

    # Reuse the project's already validated TDP decoder when present.
    try:
        from blackboxlab.tdp_decrypt import tdp_decrypt_once
        out["tdp_decrypt"] = tdp_decrypt_once(
            target,
            timeout=1.5,
            show_values=False,
        )
    except Exception as exc:
        out["tdp_decrypt"] = {
            "available": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    return out
