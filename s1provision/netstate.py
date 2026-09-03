from __future__ import annotations

import json
import subprocess
import psutil


PS_COMMAND = """
Get-NetIPConfiguration | ForEach-Object {
    [pscustomobject]@{
        InterfaceAlias = $_.InterfaceAlias
        InterfaceIndex = $_.InterfaceIndex
        IPv4Address = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
        IPv4DefaultGateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
    }
} | ConvertTo-Json -Compress
"""


def ip_configurations() -> dict:
    try:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                PS_COMMAND,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if cp.returncode == 0 and cp.stdout.strip():
            data = json.loads(cp.stdout)
            if isinstance(data, dict):
                data = [data]
            return {
                "ok": True,
                "interfaces": data,
                "error": None,
            }

        return {
            "ok": False,
            "interfaces": [],
            "error": cp.stderr.strip() or f"PowerShell exit {cp.returncode}",
        }

    except Exception as exc:
        return {
            "ok": False,
            "interfaces": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def interface_addresses() -> dict:
    out = {}

    for name, addrs in psutil.net_if_addrs().items():
        rows = []
        for addr in addrs:
            rows.append({
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
            })
        out[name] = rows

    return out
