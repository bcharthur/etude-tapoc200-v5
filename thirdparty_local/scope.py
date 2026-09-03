from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass(frozen=True)
class Scope:
    target_ip: str
    target_mac: str


def load_scope() -> Scope:
    try:
        from tapolab.config import load_scope as project_load_scope
        s = project_load_scope()
        return Scope(str(s.target_ip), str(s.target_mac))
    except Exception:
        pass

    p = Path("config/scope.json")
    if not p.exists():
        raise RuntimeError("Could not load config/scope.json")

    obj = json.loads(p.read_text(encoding="utf-8"))

    def find(o, names):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in names and isinstance(v, str) and v:
                    return v
            for v in o.values():
                hit = find(v, names)
                if hit:
                    return hit
        elif isinstance(o, list):
            for v in o:
                hit = find(v, names)
                if hit:
                    return hit
        return None

    ip = find(obj, {"target_ip", "camera_ip", "ip"})
    mac = find(obj, {"target_mac", "camera_mac", "mac"})
    if not ip or not mac:
        raise RuntimeError("Missing target_ip/target_mac in scope")
    return Scope(ip, mac)
