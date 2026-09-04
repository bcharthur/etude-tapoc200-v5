from __future__ import annotations
from pathlib import Path
import json
import re
import subprocess


def _find(o, names):
    if isinstance(o, dict):
        for k, v in o.items():
            if str(k).lower() in names and isinstance(v, str) and v:
                return v
        for v in o.values():
            hit = _find(v, names)
            if hit:
                return hit
    elif isinstance(o, list):
        for v in o:
            hit = _find(v, names)
            if hit:
                return hit
    return None


def load_scope():
    p = Path("config/scope.json")
    if not p.exists():
        raise RuntimeError("Missing config/scope.json")
    obj = json.loads(p.read_text(encoding="utf-8"))
    ip = _find(obj, {"target_ip", "camera_ip", "ip"})
    mac = _find(obj, {"target_mac", "camera_mac", "mac"})
    if not ip or not mac:
        raise RuntimeError("Missing target_ip/target_mac in config/scope.json")
    return {"target_ip": ip, "target_mac": mac}


def norm_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


def current_ssid() -> str | None:
    cp = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in cp.stdout.splitlines():
        if re.match(r"\s*BSSID\s*:", line, re.I):
            continue
        m = re.match(r"\s*SSID\s*:\s*(.+?)\s*$", line, re.I)
        if m:
            return m.group(1).strip()
    return None


def setup_gateway() -> str:
    ps = (
        'Get-NetIPConfiguration | '
        'Select-Object InterfaceAlias,@{N="IPv4DefaultGateway";'
        'E={@($_.IPv4DefaultGateway.NextHop)}} | '
        'ConvertTo-Json -Depth 4'
    )
    cp = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if cp.returncode:
        raise RuntimeError(cp.stderr.strip() or "Get-NetIPConfiguration failed")
    obj = json.loads(cp.stdout)
    rows = obj if isinstance(obj, list) else [obj]
    for row in rows:
        alias = str(row.get("InterfaceAlias") or "").lower()
        if not any(x in alias for x in ("wi-fi", "wifi", "wlan")):
            continue
        gws = row.get("IPv4DefaultGateway") or []
        if isinstance(gws, str):
            gws = [gws]
        for gw in gws:
            if gw and gw.startswith(("10.", "172.", "192.168.")):
                return gw
    raise RuntimeError("No private Wi-Fi gateway found")


def require_setup_scope():
    scope = load_scope()
    expected = "Tapo_Cam_" + norm_mac(scope["target_mac"])[-4:]
    actual = current_ssid()
    if not actual or actual.upper() != expected.upper():
        raise RuntimeError(
            f"Refusing SETUP camera query: connect to {expected!r}; current={actual!r}"
        )
    return scope, setup_gateway(), {
        "expected_ssid": expected,
        "actual_ssid": actual,
    }
