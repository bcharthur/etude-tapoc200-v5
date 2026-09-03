from __future__ import annotations

import socket
import time


def _rtsp_request(target_ip: str, uri: str, timeout: float = 2.0) -> dict:
    request = (
        f"DESCRIBE {uri} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: tapolab-blackbox/0.1\r\n"
        "\r\n"
    ).encode("ascii")

    result = {
        "target_ip": target_ip,
        "uri": uri,
        "status_line": None,
        "headers": {},
        "body_preview": None,
        "auth_required": None,
        "possible_bypass": False,
        "error": None,
        "elapsed_ms": None,
    }

    started = time.perf_counter()

    try:
        with socket.create_connection((target_ip, 554), timeout=timeout) as s:
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
                    # If there is a Content-Length, try to obtain the body too.
                    head, _, body = bytes(data).partition(b"\r\n\r\n")
                    content_len = 0
                    for line in head.decode("latin-1", errors="replace").splitlines():
                        if line.lower().startswith("content-length:"):
                            try:
                                content_len = int(line.split(":", 1)[1].strip())
                            except ValueError:
                                pass
                    if not content_len or len(body) >= content_len:
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
        result["body_preview"] = body[:4096].decode("utf-8", errors="replace") or None

        status = result["status_line"] or ""
        result["auth_required"] = "401" in status
        # A DESCRIBE without Authorization returning SDP/200 would be significant.
        result["possible_bypass"] = (
            " 200 " in status
            and (
                b"v=0" in body
                or b"m=video" in body
                or b"application/sdp" in raw.lower()
            )
        )

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def run_rtsp_loopback_regression(target_ip: str, timeout: float = 2.0) -> dict:
    """
    Regression-only test inspired by a historical older-C200 implementation
    that reportedly treated loopback-looking RTSP URLs specially.

    We connect only to target_ip. No packet is sent to localhost itself.
    """
    variants = [
        f"rtsp://{target_ip}:554/stream1",
        "rtsp://127.0.0.1:554/stream1",
        "rtsp://localhost:554/stream1",
        f"rtsp://{target_ip}:554/stream2",
        "rtsp://127.0.0.1:554/stream2",
        "rtsp://localhost:554/stream2",
    ]

    results = [_rtsp_request(target_ip, uri, timeout) for uri in variants]

    return {
        "target_ip": target_ip,
        "test": "historical_loopback_uri_regression",
        "credentials_used": False,
        "destructive": False,
        "results": results,
        "possible_bypass_observed": any(r["possible_bypass"] for r in results),
    }
