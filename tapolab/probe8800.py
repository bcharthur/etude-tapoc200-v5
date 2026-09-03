from __future__ import annotations

import socket
import time


def passive_probe_8800(
    ip: str,
    port: int = 8800,
    wait_seconds: float = 2.0,
    max_bytes: int = 4096,
) -> dict:
    """
    Connects and waits. It intentionally sends zero application bytes.
    """
    result = {
        "ip": ip,
        "port": port,
        "connected": False,
        "server_first": False,
        "bytes_received": 0,
        "ascii_preview": None,
        "hex_preview": None,
        "peer_closed": False,
        "error": None,
        "elapsed_ms": None,
    }

    started = time.perf_counter()

    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            result["connected"] = True
            s.settimeout(wait_seconds)

            try:
                data = s.recv(max_bytes)
                if data:
                    result["server_first"] = True
                    result["bytes_received"] = len(data)
                    result["ascii_preview"] = "".join(
                        chr(b) if 32 <= b < 127 else "."
                        for b in data[:256]
                    )
                    result["hex_preview"] = data[:256].hex(" ")
                else:
                    result["peer_closed"] = True
            except socket.timeout:
                pass

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result
