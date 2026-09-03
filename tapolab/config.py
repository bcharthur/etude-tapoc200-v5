from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import ipaddress
import json

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "scope.json"


@dataclass(frozen=True)
class Scope:
    device_name: str
    target_ip: str
    target_mac: str
    allowed_cidr: str
    tcp_ports: tuple[int, ...]

    @property
    def network(self):
        return ipaddress.ip_network(self.allowed_cidr, strict=False)


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def load_scope() -> Scope:
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    scope = Scope(
        device_name=raw["device_name"],
        target_ip=raw["target_ip"],
        target_mac=normalize_mac(raw["target_mac"]),
        allowed_cidr=raw["allowed_cidr"],
        tcp_ports=tuple(int(p) for p in raw.get("tcp_ports", [])),
    )
    if ipaddress.ip_address(scope.target_ip) not in scope.network:
        raise ValueError("La cible configurée est hors du CIDR autorisé.")
    return scope
