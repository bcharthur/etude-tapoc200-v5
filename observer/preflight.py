from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from memstate.scope import load_scope

from .common import build_rtsp_url, find_executable, load_env_file, redact_url, runtime_info
from .pcap import capture_interfaces


def preflight(ip: str | None = None, env_file: str | None = ".env.observer") -> dict:
    load_env_file(env_file)
    scope = load_scope()
    target = ip or scope.target_ip
    rtsp_url = build_rtsp_url(target)
    cap = capture_interfaces()
    return {
        "runtime": runtime_info(),
        "scope": {"target_ip": target, "target_mac": scope.target_mac, "source": scope.source},
        "features": {
            "wifi_netsh": os.name == "nt",
            "opencv": importlib.util.find_spec("cv2") is not None,
            "pytapo": importlib.util.find_spec("pytapo") is not None,
            "tshark": bool(find_executable("tshark")),
            "dumpcap": bool(find_executable("dumpcap")),
            "pktmon": bool(find_executable("pktmon")),
        },
        "credentials": {
            "tapo_api_configured": bool(os.getenv("TAPO_USER") and os.getenv("TAPO_PASSWORD")),
            "rtsp_configured": bool(rtsp_url),
            "rtsp_url": redact_url(rtsp_url),
            "env_file_exists": bool(env_file and Path(env_file).exists()),
        },
        "capture": cap,
        "notes": [
            "Base TCP/ARP/state observation works with the Python standard library plus the existing project.",
            "RTSP is optional and requires OpenCV plus camera-account credentials.",
            "Tapo API observation is optional and only calls a whitelisted read-only info getter.",
            "Wireshark capture requires Npcap; Windows pktmon is used as a host-stack fallback and normally requires an elevated shell.",
            "Host-stack capture does NOT reveal ambient camera<->AP/cloud traffic when the laptop is not on-path.",
            "For non-disruptive observation of camera 802.11 handshakes, use the Alfa adapter in passive monitor mode; no injection is required.",
            "This tool correlates external observations; it does not dump camera RAM.",
        ],
    }
