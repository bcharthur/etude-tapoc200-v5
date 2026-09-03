from __future__ import annotations
import concurrent.futures
import ipaddress
import platform
import re
import subprocess
from .config import normalize_mac

ARP_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F:-]{17})\s+"
    r"(?P<kind>\S+)\s*$"
)


def ping(ip: str, timeout_ms: int = 500) -> bool:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    return subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def read_arp_table() -> dict[str, str]:
    proc = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    out = {}
    for line in proc.stdout.splitlines():
        m = ARP_RE.match(line)
        if m:
            out[m.group("ip")] = normalize_mac(m.group("mac"))
    return out


def ping_sweep(cidr: str, workers: int = 64) -> list[str]:
    hosts = [str(x) for x in ipaddress.ip_network(cidr, strict=False).hosts()]
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, ok in zip(hosts, pool.map(ping, hosts)):
            if ok:
                alive.append(ip)
    return alive


def discover_ip_by_mac(cidr: str, wanted_mac: str) -> str | None:
    ping_sweep(cidr)
    wanted_mac = normalize_mac(wanted_mac)
    for ip, mac in read_arp_table().items():
        if normalize_mac(mac) == wanted_mac:
            return ip
    return None
