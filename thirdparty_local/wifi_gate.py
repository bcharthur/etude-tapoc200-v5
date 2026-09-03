from __future__ import annotations

import re
import subprocess

from .scope import load_scope


def current_wifi_ssid() -> str | None:
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
            value = m.group(1).strip()
            if value:
                return value
    return None


def expected_setup_ssid() -> str:
    scope = load_scope()
    suffix = scope.target_mac.replace(":", "").replace("-", "")[-4:].upper()
    return f"Tapo_Cam_{suffix}"


def require_scoped_setup_ssid():
    actual = current_wifi_ssid()
    expected = expected_setup_ssid()
    ok = bool(actual and actual.upper() == expected.upper())

    result = {
        "actual_ssid": actual,
        "expected_ssid": expected,
        "matches": ok,
    }

    if not ok:
        raise RuntimeError(
            f"Refusing: connect Windows Wi-Fi to scoped setup SSID "
            f"{expected!r} first (current: {actual!r})."
        )
    return result
