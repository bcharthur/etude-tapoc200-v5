from __future__ import annotations

import json
import socket
import time


BOUNDARY = "--client-stream-boundary--"


def _recv_headers(sock: socket.socket, timeout: float, max_bytes: int = 65536) -> tuple[bytes, bytes]:
    sock.settimeout(timeout)
    data = bytearray()

    while len(data) < max_bytes:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
        if b"\r\n\r\n" in data:
            break

    return bytes(data).partition(b"\r\n\r\n")[0], bytes(data).partition(b"\r\n\r\n")[2]


def _parse_headers(head: bytes) -> tuple[str | None, dict]:
    lines = head.decode("latin-1", errors="replace").splitlines()
    status = lines[0] if lines else None
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.setdefault(key.strip().lower(), []).append(value.strip())
    return status, headers


def stream_8800_challenge(target_ip: str, timeout: float = 2.0) -> dict:
    """
    Send the canonical empty POST /stream with NO Authorization.
    Expected secure behavior is a 401 challenge.
    """
    request = (
        "POST /stream HTTP/1.1\r\n"
        f"Host: {target_ip}:8800\r\n"
        f"Content-Type: multipart/mixed; boundary={BOUNDARY}\r\n"
        "User-Agent: tapolab-blackbox/0.1\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode("ascii")

    started = time.perf_counter()
    result = {
        "target_ip": target_ip,
        "port": 8800,
        "request": "POST /stream (no Authorization, zero body)",
        "status_line": None,
        "headers": {},
        "body_preview": None,
        "auth_challenges": [],
        "preauth_accepted": False,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 8800), timeout=timeout) as s:
            s.sendall(request)
            head, body = _recv_headers(s, timeout)

        status, headers = _parse_headers(head)
        result["status_line"] = status
        result["headers"] = headers
        result["auth_challenges"] = headers.get("www-authenticate", [])
        result["body_preview"] = body[:2048].decode("utf-8", errors="replace") or None
        result["preauth_accepted"] = bool(status and " 200 " in status)

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def stream_8800_preauth_preview_probe(target_ip: str, timeout: float = 2.0) -> dict:
    """
    Bounded negative test:
    - no credentials
    - no Authorization
    - asks for a normal preview request
    - reads only a small capped response

    If media begins before authentication, flag it.
    """
    preview = {
        "type": "request",
        "seq": 1,
        "params": {
            "preview": {
                "channels": [0],
                "resolutions": ["HD"],
                "audio": ["default"],
            },
            "method": "get",
        },
    }

    body = json.dumps(preview, separators=(",", ":")).encode("utf-8")

    request = (
        "POST /stream HTTP/1.1\r\n"
        f"Host: {target_ip}:8800\r\n"
        f"Content-Type: multipart/mixed; boundary={BOUNDARY}\r\n"
        "User-Agent: tapolab-blackbox/0.1\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    started = time.perf_counter()
    result = {
        "target_ip": target_ip,
        "port": 8800,
        "request": "POST /stream + preview JSON (no Authorization)",
        "status_line": None,
        "headers": {},
        "bytes_after_headers": 0,
        "body_ascii_preview": None,
        "media_signature_seen": False,
        "preauth_stream_possible": False,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 8800), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)

            data = bytearray()
            deadline = time.time() + timeout
            while time.time() < deadline and len(data) < 32768:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)

        raw = bytes(data)
        head, sep, rest = raw.partition(b"\r\n\r\n")
        status, headers = _parse_headers(head)

        result["status_line"] = status
        result["headers"] = headers
        result["bytes_after_headers"] = len(rest)
        result["body_ascii_preview"] = "".join(
            chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "."
            for b in rest[:2048]
        ) or None

        lower = raw.lower()
        result["media_signature_seen"] = any(
            marker in lower
            for marker in (
                b"video/mp2t",
                b"content-type: video/",
                b"device-stream-boundary",
            )
        )

        result["preauth_stream_possible"] = (
            bool(status and " 200 " in status)
            or result["media_signature_seen"]
        )

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result
