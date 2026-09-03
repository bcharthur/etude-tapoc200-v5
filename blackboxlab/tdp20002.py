from __future__ import annotations

import json
import socket
import time


DISCOVERY_QUERY_2 = bytes.fromhex("020000010000000000000000463cb5d3")


def tdp_20002_unicast(target_ip: str, timeout: float = 2.0) -> dict:
    """
    Scoped unicast discovery probe to the already-authorized target only.
    No LAN broadcast is emitted by this command.
    """
    result = {
        "target_ip": target_ip,
        "target_port": 20002,
        "query_hex": DISCOVERY_QUERY_2.hex(),
        "response_received": False,
        "source": None,
        "bytes": 0,
        "header_hex": None,
        "json": None,
        "json_parse_error": None,
        "raw_hex_preview": None,
        "elapsed_ms": None,
        "error": None,
    }

    started = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(DISCOVERY_QUERY_2, (target_ip, 20002))
            data, addr = s.recvfrom(65535)

        result["response_received"] = True
        result["source"] = {"ip": addr[0], "port": addr[1]}
        result["bytes"] = len(data)
        result["header_hex"] = data[:16].hex()
        result["raw_hex_preview"] = data[:256].hex()

        if len(data) >= 16:
            payload = data[16:]
            try:
                result["json"] = json.loads(payload.decode("utf-8"))
            except Exception as exc:
                result["json_parse_error"] = f"{type(exc).__name__}: {exc}"

    except socket.timeout:
        pass
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result
