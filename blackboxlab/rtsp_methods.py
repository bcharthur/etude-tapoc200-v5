from __future__ import annotations

import socket
import time


def _send(target_ip: str, request: str, timeout: float = 2.0) -> dict:
    started = time.perf_counter()
    result = {
        "request_line": request.split("\r\n", 1)[0],
        "status_line": None,
        "headers": {},
        "body_preview": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 554), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request.encode("ascii"))

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
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())

        result["headers"] = headers
        result["body_preview"] = body[:2048].decode("utf-8", errors="replace") or None

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def rtsp_method_matrix(target_ip: str, timeout: float = 2.0) -> dict:
    root = f"rtsp://{target_ip}:554/"
    stream = f"rtsp://{target_ip}:554/stream1"

    requests = [
        (
            "OPTIONS",
            f"OPTIONS {root} RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            True,
        ),
        (
            "DESCRIBE",
            f"DESCRIBE {stream} RTSP/1.0\r\n"
            "CSeq: 2\r\n"
            "Accept: application/sdp\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            False,
        ),
        (
            "SETUP",
            f"SETUP {stream}/trackID=0 RTSP/1.0\r\n"
            "CSeq: 3\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            False,
        ),
        (
            "PLAY",
            f"PLAY {stream} RTSP/1.0\r\n"
            "CSeq: 4\r\n"
            "Range: npt=0.000-\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            False,
        ),
        (
            "GET_PARAMETER",
            f"GET_PARAMETER {stream} RTSP/1.0\r\n"
            "CSeq: 5\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            False,
        ),
        (
            "TEARDOWN",
            f"TEARDOWN {stream} RTSP/1.0\r\n"
            "CSeq: 6\r\n"
            "User-Agent: tapolab-blackbox/0.2\r\n\r\n",
            False,
        ),
    ]

    results = []
    candidates = []

    for name, request, public_expected in requests:
        r = _send(target_ip, request, timeout)
        r["method"] = name
        r["public_2xx_expected"] = public_expected

        status = r.get("status_line") or ""
        two_xx = any(f" {code} " in status for code in range(200, 300))

        if two_xx and not public_expected:
            candidates.append({
                "method": name,
                "status_line": status,
                "reason": "Non-public RTSP method returned 2xx without Authorization.",
            })

        results.append(r)

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "results": results,
        "candidate_auth_gaps": candidates,
    }
