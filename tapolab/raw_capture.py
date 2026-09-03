from __future__ import annotations

import ipaddress
import os
import platform
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import psutil


DLT_RAW = 101  # Raw IPv4 packets, no Ethernet header.


@dataclass
class InterfaceInfo:
    name: str
    ipv4: list[str]


def list_ipv4_interfaces() -> list[InterfaceInfo]:
    results: list[InterfaceInfo] = []
    for name, addrs in psutil.net_if_addrs().items():
        ips = []
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ips.append(addr.address)
        if ips:
            results.append(InterfaceInfo(name=name, ipv4=ips))
    return results


def route_local_ip(target_ip: str) -> str:
    """
    Ask the OS routing table which local IPv4 address would be used to reach
    the target. No packet needs to be sent for UDP connect().
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def _ipv4_endpoints(packet: bytes) -> tuple[str, str] | None:
    if len(packet) < 20:
        return None

    version = packet[0] >> 4
    if version != 4:
        return None

    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None

    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])
    return src, dst


def _pcap_global_header() -> bytes:
    # little endian PCAP, microsecond timestamps, DLT_RAW.
    return struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        DLT_RAW,
    )


def _pcap_record(packet: bytes, now: float) -> bytes:
    sec = int(now)
    usec = int((now - sec) * 1_000_000)
    length = len(packet)
    return struct.pack("<IIII", sec, usec, length, length) + packet


def capture_windows_ipv4(
    *,
    local_ip: str,
    target_ip: str,
    output: Path,
    seconds: int,
) -> dict:
    if platform.system().lower() != "windows":
        raise RuntimeError("capture_windows_ipv4 est réservé à Windows.")

    ipaddress.ip_address(local_ip)
    ipaddress.ip_address(target_ip)

    output.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    packets_seen = 0
    packets_written = 0
    bytes_written = 0
    error = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    try:
        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows promiscuous receive mode for IPv4 on the selected interface.
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        sock.settimeout(0.5)

        with output.open("wb") as f:
            f.write(_pcap_global_header())

            deadline = started + seconds
            while time.time() < deadline:
                try:
                    packet, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                packets_seen += 1
                endpoints = _ipv4_endpoints(packet)
                if not endpoints:
                    continue

                src, dst = endpoints
                if src != target_ip and dst != target_ip:
                    continue

                rec = _pcap_record(packet, time.time())
                f.write(rec)
                packets_written += 1
                bytes_written += len(packet)

    except PermissionError as exc:
        error = (
            "Permission refusée. Sous Windows, lance PowerShell/PyCharm "
            "en administrateur pour utiliser SIO_RCVALL. "
            f"Détail: {exc}"
        )
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        sock.close()

    elapsed = round(time.time() - started, 2)

    return {
        "ok": error is None,
        "platform": platform.system(),
        "local_ip": local_ip,
        "target_ip": target_ip,
        "seconds_requested": seconds,
        "elapsed_s": elapsed,
        "packets_seen": packets_seen,
        "packets_written": packets_written,
        "captured_ip_bytes": bytes_written,
        "output": str(output),
        "file_size": output.stat().st_size if output.exists() else 0,
        "error": error,
        "capture_scope": (
            "IPv4 packets visible by the selected Windows interface, "
            "filtered to src/dst target IP."
        ),
    }
