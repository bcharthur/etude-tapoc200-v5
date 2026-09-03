from __future__ import annotations

import ipaddress
import json
import subprocess


def setup_gateway() -> str:
    ps = r'''
$ErrorActionPreference="Stop"
Get-NetIPConfiguration |
Select-Object InterfaceAlias,InterfaceIndex,
  @{N="IPv4Address";E={@($_.IPv4Address.IPAddress)}},
  @{N="IPv4DefaultGateway";E={@($_.IPv4DefaultGateway.NextHop)}} |
ConvertTo-Json -Depth 5
'''

    cp = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or "Get-NetIPConfiguration failed")

    obj = json.loads(cp.stdout)
    rows = obj if isinstance(obj, list) else [obj]

    for row in rows:
        alias = str(row.get("InterfaceAlias") or "").lower()
        if not any(x in alias for x in ("wi-fi", "wifi", "wlan")):
            continue

        gateways = row.get("IPv4DefaultGateway") or []
        if isinstance(gateways, str):
            gateways = [gateways]

        for value in gateways:
            if not value:
                continue
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            if addr.version == 4 and addr.is_private:
                return value

    raise RuntimeError("No private IPv4 gateway found on Wi-Fi interface")
