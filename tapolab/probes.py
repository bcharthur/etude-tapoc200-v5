import socket
import time


def tcp_probe(ip: str, port: int, timeout: float = 1.0) -> dict:
    started = time.perf_counter()
    result = {
        "ip": ip,
        "port": port,
        "transport": "tcp",
        "open": False,
        "error": None,
        "elapsed_ms": None,
    }
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            result["open"] = True
    except OSError as exc:
        result["error"] = type(exc).__name__
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def probe_ports(ip: str, ports, timeout: float = 1.0) -> list[dict]:
    return [tcp_probe(ip, p, timeout) for p in ports]
