from __future__ import annotations

import json
import re
from pathlib import Path

from memstate.evidence import write_json

from .common import append_jsonl, read_jsonl


_PROVISIONING_RE = re.compile(r"(?:tapo|tp[-_ ]?link|c200)", re.I)


def _first(events: list[dict], source: str, event: str) -> dict | None:
    return next((x for x in events if x.get("source") == source and x.get("event") == event), None)


def merge_timeline(run: Path) -> list[dict]:
    events = read_jsonl(run / "timeline.jsonl") + read_jsonl(run / "markers.jsonl")
    events.sort(key=lambda x: (float(x.get("t", 0.0)), str(x.get("utc", ""))))
    merged = run / "merged-timeline.jsonl"
    if merged.exists():
        merged.unlink()
    for obj in events:
        append_jsonl(merged, obj)
    return events


def build_report(run: Path) -> dict:
    events = merge_timeline(run)
    tcp_down = [x for x in events if x.get("source") == "tcp" and x.get("event") == "PORT_DOWN"]
    tcp_up = [x for x in events if x.get("source") == "tcp" and x.get("event") == "PORT_UP"]
    rtsp_down = _first(events, "rtsp", "DISCONNECTED")
    new_ssids = [x for x in events if x.get("source") == "wifi" and x.get("event") == "SSID_APPEARED"]
    provisioning_ssids = [x for x in new_ssids if _PROVISIONING_RE.search(str(x.get("ssid", "")))]
    target_bssid = [x for x in events if x.get("source") == "wifi" and x.get("event") == "BSSID_APPEARED" and x.get("target_mac_match")]

    had_loss = bool(tcp_down or rtsp_down)
    later_up = False
    if tcp_down:
        first_down_t = min(float(x.get("t", 0.0)) for x in tcp_down)
        later_up = any(float(x.get("t", 0.0)) > first_down_t for x in tcp_up)

    if provisioning_ssids or target_bssid:
        classification = "POTENTIAL_PROVISIONING_AFTER_CONNECTIVITY_CHANGE"
        confidence = "medium"
    elif had_loss and later_up:
        classification = "CONNECTIVITY_LOSS_RECOVERED"
        confidence = "high"
    elif had_loss:
        classification = "CONNECTIVITY_LOSS_NO_RECOVERY_OBSERVED"
        confidence = "high"
    else:
        classification = "NO_CONNECTIVITY_LOSS_OBSERVED"
        confidence = "high"

    report = {
        "classification": classification,
        "confidence": confidence,
        "important": "This observer does not read camera RAM. It correlates external network/API/RTSP/Wi-Fi evidence with existing memorylab state snapshots.",
        "event_count": len(events),
        "tcp_down": tcp_down,
        "rtsp_first_disconnect": rtsp_down,
        "new_ssids": new_ssids,
        "provisioning_like_ssids": provisioning_ssids,
        "target_mac_seen_as_new_bssid": target_bssid,
        "operator_markers": [x for x in events if x.get("source") == "operator"],
    }
    write_json(run / "summary.json", report)
    return report
