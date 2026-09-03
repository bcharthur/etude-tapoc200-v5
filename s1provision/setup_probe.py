from __future__ import annotations

import ipaddress

from .wifi_windows import connected_wifi
from .netstate import ip_configurations
from .probes import tcp_probe, https_discover


def _private_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
        return addr.version == 4 and addr.is_private
    except ValueError:
        return False


def _pick_wifi_config(configs: list[dict]) -> dict | None:
    for row in configs:
        alias = (row.get("InterfaceAlias") or "").lower()
        if "wi-fi" in alias or "wifi" in alias or "wlan" in alias:
            return row
    return None


def setup_network_probe() -> dict:
    wifi = connected_wifi()
    ssid = wifi.get("ssid") or ""

    result = {
        "connected_wifi": wifi,
        "authorized_setup_network": False,
        "network_configuration": None,
        "candidate_camera_ip": None,
        "tcp": None,
        "https_discover": None,
        "error": None,
    }

    if not ssid.lower().startswith("tapo_cam_"):
        result["error"] = (
            "Current Wi-Fi SSID is not Tapo_Cam_*. "
            "Connect manually to your camera's setup SSID first."
        )
        return result

    result["authorized_setup_network"] = True

    configs = ip_configurations()
    result["network_configuration"] = configs

    if not configs.get("ok"):
        result["error"] = configs.get("error")
        return result

    wifi_cfg = _pick_wifi_config(configs.get("interfaces") or [])
    if not wifi_cfg:
        result["error"] = "Could not identify the Windows Wi-Fi IP configuration."
        return result

    gateways = wifi_cfg.get("IPv4DefaultGateway") or []
    candidate = next((g for g in gateways if _private_ipv4(g)), None)

    if not candidate:
        result["error"] = (
            "No private IPv4 default gateway found on the Tapo setup Wi-Fi. "
            "No guessing or subnet sweep was performed."
        )
        return result

    result["candidate_camera_ip"] = candidate
    result["tcp"] = {
        str(port): tcp_probe(candidate, port, timeout=0.8)
        for port in (443, 554, 2020, 8800)
    }

    if result["tcp"]["443"]["open"]:
        result["https_discover"] = https_discover(candidate, timeout=2.0)

    return result
