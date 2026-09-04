from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from .common import append_jsonl, run_command, sanitize_text


_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.I)
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-f:-]{17})", re.I)
_SIGNAL_RE = re.compile(r"^\s*(?:Signal)\s*:\s*(\d+)%", re.I)
_CHANNEL_RE = re.compile(r"^\s*(?:Channel|Canal)\s*:\s*(\d+)", re.I)


def parse_netsh_networks(text: str) -> list[dict]:
    networks: list[dict] = []
    current_ssid: str | None = None
    current_bssid: dict | None = None
    for line in text.splitlines():
        m = _SSID_RE.match(line)
        if m:
            current_ssid = m.group(1).strip()
            current_bssid = None
            continue
        m = _BSSID_RE.match(line)
        if m:
            current_bssid = {
                "ssid": current_ssid or "",
                "bssid": m.group(1).lower().replace("-", ":"),
                "signal": None,
                "channel": None,
            }
            networks.append(current_bssid)
            continue
        if current_bssid is not None:
            m = _SIGNAL_RE.match(line)
            if m:
                current_bssid["signal"] = int(m.group(1))
                continue
            m = _CHANNEL_RE.match(line)
            if m:
                current_bssid["channel"] = int(m.group(1))
    return networks


class WifiScanner(threading.Thread):
    def __init__(self, *, interval: float, timeline, run: Path, stop_event: threading.Event, target_mac: str | None = None):
        super().__init__(name="observer-wifi", daemon=True)
        self.interval = max(1.0, interval)
        self.timeline = timeline
        self.run_dir = run
        self.stop_event = stop_event
        self.target_mac = target_mac.lower().replace("-", ":") if target_mac else None
        self.sample_path = run / "wifi.jsonl"
        self.baseline_ssids: set[str] | None = None
        self.baseline_bssids: set[str] | None = None
        self.seen_ssids: set[str] = set()
        self.seen_bssids: set[str] = set()

    def run(self):
        if os.name != "nt":
            self.timeline.emit("wifi", "SCANNER_DISABLED", reason="netsh WLAN scanner requires Windows")
            return
        self.timeline.emit("wifi", "SCANNER_START", interval=self.interval)
        seq = 0
        while not self.stop_event.is_set():
            rc, out, err = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=8.0)
            networks = parse_netsh_networks(out) if rc == 0 else []
            ssids = {x.get("ssid", "") for x in networks if x.get("ssid")}
            bssids = {x.get("bssid", "") for x in networks if x.get("bssid")}
            append_jsonl(self.sample_path, {"seq": seq, "rc": rc, "networks": networks, "error": sanitize_text(err) if rc else None})

            if self.baseline_ssids is None and rc == 0:
                self.baseline_ssids = set(ssids)
                self.baseline_bssids = set(bssids)
                self.seen_ssids |= ssids
                self.seen_bssids |= bssids
                self.timeline.emit("wifi", "BASELINE", ssid_count=len(ssids), bssid_count=len(bssids), ssids=sorted(ssids))
            elif rc == 0:
                for ssid in sorted(ssids - self.seen_ssids):
                    self.timeline.emit("wifi", "SSID_APPEARED", ssid=ssid)
                for bssid in sorted(bssids - self.seen_bssids):
                    hit = next((x for x in networks if x.get("bssid") == bssid), {})
                    self.timeline.emit("wifi", "BSSID_APPEARED", bssid=bssid, ssid=hit.get("ssid"), target_mac_match=(bssid == self.target_mac))
                self.seen_ssids |= ssids
                self.seen_bssids |= bssids
            else:
                self.timeline.emit("wifi", "SCAN_ERROR", rc=rc, error=sanitize_text(err))
            seq += 1
            self.stop_event.wait(self.interval)
        self.timeline.emit("wifi", "SCANNER_STOP")
