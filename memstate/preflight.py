from __future__ import annotations

from pathlib import Path

from .network import tcp_probe
from .scope import load_scope


SERVICE_PORTS = {
    "rtsp": 554,
    "https": 443,
    "streamd": 8800,
}


def require_scoped_service(service: str, timeout: float = 0.6) -> dict:
    scope = load_scope()
    if service not in SERVICE_PORTS:
        raise ValueError(f"Unknown service {service!r}")

    port = SERVICE_PORTS[service]
    probe = tcp_probe(scope.target_ip, port, timeout=timeout)

    result = {
        "target_ip": scope.target_ip,
        "service": service,
        "port": port,
        "open": probe["open"],
        "probe": probe,
    }

    if not probe["open"]:
        raise RuntimeError(
            f"Preflight failed: scoped target {scope.target_ip}:{port} "
            f"({service}) is not reachable. No fuzz cases were sent. "
            f"If the camera is still in SETUP, re-pair it before running "
            f"NORMAL-state fuzzing."
        )

    return result


def require_file(path: str, label: str = "file") -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"{label} does not exist: {p}. "
            "This command analyzes an already acquired artifact; "
            "it does not acquire hardware flash automatically."
        )
    if not p.is_file():
        raise RuntimeError(f"{label} is not a file: {p}")
    return p


def require_directory(path: str, label: str = "directory") -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"{label} does not exist: {p}. "
            "Extract/acquire the firmware first."
        )
    if not p.is_dir():
        raise RuntimeError(f"{label} is not a directory: {p}")
    return p
