from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scope:
    target_ip: str
    target_mac: str | None
    source: str


def _walk(obj, keys):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys and isinstance(v, str) and v:
                return v
        for v in obj.values():
            hit = _walk(v, keys)
            if hit:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = _walk(v, keys)
            if hit:
                return hit
    return None


def load_scope() -> Scope:
    # Prefer the project's existing loader if available.
    try:
        from tapolab.config import load_scope as project_load_scope
        s = project_load_scope()
        ip = getattr(s, "target_ip", None)
        mac = getattr(s, "target_mac", None)
        if ip:
            return Scope(str(ip), str(mac) if mac else None, "tapolab.config")
    except Exception:
        pass

    p = Path("config/scope.json")
    if not p.exists():
        raise FileNotFoundError(
            "Could not load project scope. Expected tapolab.config.load_scope() "
            "or config/scope.json."
        )

    obj = json.loads(p.read_text(encoding="utf-8"))
    ip = _walk(obj, {"target_ip", "ip", "camera_ip"})
    mac = _walk(obj, {"target_mac", "mac", "camera_mac"})

    if not ip:
        raise RuntimeError("No target IP found in config/scope.json")

    return Scope(ip, mac, str(p))
