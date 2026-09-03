from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .wifi_windows import scan_networks, wifi_diagnose
from .probes import tcp_probe


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def watch_transition(
    target_ip: str,
    output: Path,
    *,
    seconds: int = 180,
    interval: float = 1.0,
    allow_unreliable_wifi: bool = False,
) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)

    preflight = wifi_diagnose()

    if (
        not preflight.get("ready_for_setup_ssid_observation")
        and not allow_unreliable_wifi
    ):
        return {
            "started": False,
            "output": str(output),
            "preflight": preflight,
            "error": (
                "Wi-Fi scan preflight is not reliable. Fix Wi-Fi scanning first, "
                "or explicitly use --allow-unreliable-wifi if you only want LAN timing."
            ),
        }

    started = time.time()
    first_setup_seen = None
    first_target_down = None
    first_target_up_after_down = None
    rows = 0
    unreliable_samples = 0

    with output.open("w", encoding="utf-8") as fh:
        while time.time() - started < seconds:
            tcp = {
                str(port): tcp_probe(target_ip, port, timeout=0.35)
                for port in (443, 554, 2020, 8800)
            }

            reachable = any(v["open"] for v in tcp.values())

            try:
                wifi = scan_networks()
            except Exception as exc:
                wifi = {
                    "ok": False,
                    "scan_reliable": False,
                    "tapo_setup_networks": [],
                    "error": f"{type(exc).__name__}: {exc}",
                }

            if not wifi.get("scan_reliable"):
                unreliable_samples += 1

            tapo_networks = wifi.get("tapo_setup_networks") or []
            setup_seen = bool(tapo_networks)

            now = _utcnow()

            if setup_seen and first_setup_seen is None:
                first_setup_seen = now

            if not reachable and first_target_down is None:
                first_target_down = now

            if (
                reachable
                and first_target_down is not None
                and first_target_up_after_down is None
            ):
                first_target_up_after_down = now

            row = {
                "ts": now,
                "target_ip": target_ip,
                "target_reachable_any_tcp": reachable,
                "tcp": tcp,
                "wifi_scan_reliable": wifi.get("scan_reliable"),
                "wifi_scan_diagnostic": wifi.get("diagnostic"),
                "tapo_setup_networks": tapo_networks,
            }

            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
            rows += 1

            time.sleep(interval)

    return {
        "started": True,
        "output": str(output),
        "rows": rows,
        "seconds_requested": seconds,
        "preflight": preflight,
        "wifi_unreliable_samples": unreliable_samples,
        "first_target_down": first_target_down,
        "first_tapo_setup_ssid_seen": first_setup_seen,
        "first_target_up_after_down": first_target_up_after_down,
        "interpretation": {
            "target_transition_observed": first_target_down is not None,
            "setup_ssid_transition_observed": first_setup_seen is not None,
        },
        "note": (
            "No reset, Wi-Fi connection or configuration is automated."
        ),
    }
