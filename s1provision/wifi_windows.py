from __future__ import annotations

import json
import re
import subprocess
import time


SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.I)
BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*(.*)$", re.I)

KEY_VALUE_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$")

BLOCK_HINTS = (
    "location",
    "localisation",
    "emplacement",
    "access is denied",
    "accès refusé",
    "permission",
)


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "cp850", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode(errors="replace")


def _run(cmd: list[str], timeout: int = 8) -> dict:
    cp = subprocess.run(
        cmd,
        capture_output=True,
        text=False,
        timeout=timeout,
        check=False,
    )
    return {
        "returncode": cp.returncode,
        "stdout": _decode(cp.stdout or b""),
        "stderr": _decode(cp.stderr or b""),
    }


def _run_netsh(args: list[str]) -> dict:
    return _run(["netsh", *args])


def _norm(s: str) -> str:
    return (
        s.strip()
        .lower()
        .replace("’", "'")
        .replace("é", "e")
        .replace("è", "e")
        .replace("ê", "e")
        .replace("à", "a")
        .replace("î", "i")
        .replace("ô", "o")
        .replace("û", "u")
    )


def adapter_status() -> dict:
    ps = """
$rows = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match 'Wi-Fi|WiFi|WLAN' -or
        $_.InterfaceDescription -match 'Wireless|Wi-Fi|WiFi|802\\.11'
    } |
    Select-Object Name, InterfaceDescription, Status, MediaConnectionState,
                  ifIndex, MacAddress, LinkSpeed

$rows | ConvertTo-Json -Compress
"""
    result = _run(
        ["powershell", "-NoProfile", "-Command", ps],
        timeout=10,
    )

    rows = []
    parse_error = None

    if result["returncode"] == 0 and result["stdout"].strip():
        try:
            obj = json.loads(result["stdout"])
            rows = obj if isinstance(obj, list) else [obj]
        except Exception as exc:
            parse_error = f"{type(exc).__name__}: {exc}"

    return {
        "ok": result["returncode"] == 0 and parse_error is None,
        "adapters": rows,
        "parse_error": parse_error,
        "stderr": result["stderr"].strip() or None,
    }


def connected_wifi() -> dict:
    res = _run_netsh(["wlan", "show", "interfaces"])
    text = res["stdout"]

    result = {
        "ssid": None,
        "bssid": None,
        "state": None,
        "raw_available": bool(text),
        "returncode": res["returncode"],
    }

    for line in text.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = _norm(key)
        value = value.strip()

        if key == "ssid":
            result["ssid"] = value
        elif key == "bssid":
            result["bssid"] = value
        elif key in {"state", "etat"}:
            result["state"] = value

    return result


def scan_networks() -> dict:
    started = time.perf_counter()
    res = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
    text = res["stdout"]
    combined = (text + "\n" + res["stderr"]).lower()

    networks = []
    current = None
    current_bssid = None

    for line in text.splitlines():
        m = SSID_RE.match(line)
        if m:
            current = {
                "ssid": m.group(1).strip(),
                "network_type": None,
                "authentication": None,
                "encryption": None,
                "bssids": [],
            }
            networks.append(current)
            current_bssid = None
            continue

        m = BSSID_RE.match(line)
        if m and current is not None:
            current_bssid = {
                "bssid": m.group(1).strip(),
                "signal_percent": None,
                "radio_type": None,
                "band": None,
                "channel": None,
            }
            current["bssids"].append(current_bssid)
            continue

        kv = KEY_VALUE_RE.match(line)
        if not kv:
            continue

        key = _norm(kv.group(1))
        value = kv.group(2).strip()

        if current is not None and current_bssid is None:
            if key in {"type de reseau", "network type"}:
                current["network_type"] = value
            elif key in {"authentification", "authentication"}:
                current["authentication"] = value
            elif key in {"chiffrement", "encryption"}:
                current["encryption"] = value

        if current_bssid is not None:
            if key == "signal":
                m_signal = re.search(r"(\d+)%", value)
                if m_signal:
                    current_bssid["signal_percent"] = int(m_signal.group(1))
            elif key in {"type de radio", "radio type"}:
                current_bssid["radio_type"] = value
            elif key in {"bande", "band"}:
                current_bssid["band"] = value
            elif key in {"canal", "channel"}:
                m_channel = re.search(r"\d+", value)
                if m_channel:
                    current_bssid["channel"] = int(m_channel.group(0))

    tapo = [
        n for n in networks
        if (n.get("ssid") or "").lower().startswith("tapo_cam_")
    ]

    blocked_hint = next(
        (hint for hint in BLOCK_HINTS if hint in combined),
        None,
    )

    reliable = (
        res["returncode"] == 0
        and blocked_hint is None
        and len(networks) > 0
    )

    diagnostic = None
    if blocked_hint:
        diagnostic = (
            "Windows/netsh appears to be blocking WLAN scan information "
            f"(matched hint: {blocked_hint!r})."
        )
    elif res["returncode"] != 0:
        diagnostic = (
            f"netsh returned exit code {res['returncode']}: "
            f"{res['stderr'].strip() or 'no stderr'}"
        )
    elif not networks:
        diagnostic = (
            "netsh returned zero parsed networks. This is not proof that no AP exists."
        )

    return {
        "ok": res["returncode"] == 0,
        "scan_reliable": reliable,
        "network_count": len(networks),
        "tapo_setup_networks": tapo,
        "diagnostic": diagnostic,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "raw_preview": text[:2500],
    }


def wifi_diagnose() -> dict:
    scan = scan_networks()
    connected = connected_wifi()
    adapters = adapter_status()

    recommendations = []

    # A disconnected adapter is perfectly acceptable for passive scanning.
    # Only warn when the scan itself is unreliable.
    if not scan.get("scan_reliable"):
        recommendations.append(
            "The current WLAN scan is not reliable. Do not use network_count=0 "
            "to conclude that Tapo_Cam_* is absent."
        )
        recommendations.append(
            "Check Wi-Fi radio, WLAN AutoConfig, driver and Windows Location/privacy."
        )

    return {
        "ready_for_setup_ssid_observation": scan.get("scan_reliable", False),
        "scan": scan,
        "connected": connected,
        "adapters": adapters,
        "recommendations": recommendations,
        "note": (
            "Wi-Fi may remain disconnected while scanning. "
            "Disconnected does not mean the radio is disabled when networks are visible."
        ),
    }
