from __future__ import annotations

import socket
import time


def _send(
    target_ip: str,
    uri: str,
    *,
    session_header: str | None = None,
    timeout: float = 2.0,
) -> dict:
    lines = [
        f"TEARDOWN {uri} RTSP/1.0",
        "CSeq: 1",
        "User-Agent: tapolab-blackbox/0.3",
    ]

    if session_header is not None:
        lines.append(f"Session: {session_header}")

    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    started = time.perf_counter()
    result = {
        "uri": uri,
        "session_header": session_header,
        "status_line": None,
        "headers": {},
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((target_ip, 554), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)

            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 32768:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)

        head = bytes(data).partition(b"\r\n\r\n")[0]
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

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def characterize_teardown(target_ip: str, timeout: float = 2.0) -> dict:
    cases = [
        (f"rtsp://{target_ip}:554/stream1", None),
        (f"rtsp://{target_ip}:554/stream2", None),
        (f"rtsp://{target_ip}:554/does-not-exist", None),
        (f"rtsp://{target_ip}:554/", None),
        (f"rtsp://{target_ip}:554/stream1", "00000000"),
        (f"rtsp://{target_ip}:554/stream1", "tapolab-bogus-session"),
    ]

    results = [
        _send(
            target_ip,
            uri,
            session_header=session,
            timeout=timeout,
        )
        for uri, session in cases
    ]

    statuses = [r.get("status_line") for r in results]
    all_200 = bool(statuses) and all(s and " 200 " in s for s in statuses)

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "session_established_before_test": False,
        "results": results,
        "all_variants_return_200": all_200,
        "assessment": (
            "likely_stateless_noop"
            if all_200
            else "response_depends_on_uri_or_session_header"
        ),
        "note": (
            "A 200 response alone has no demonstrated security impact. "
            "Impact would require affecting a real established session."
        ),
    }
