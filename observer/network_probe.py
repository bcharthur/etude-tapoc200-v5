from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from memstate.network import tcp_probe

from .common import append_jsonl, run_command


class NetworkProbe(threading.Thread):
    def __init__(self, *, ip: str, ports: list[int], interval: float, timeline, run: Path, stop_event: threading.Event):
        super().__init__(name="observer-network", daemon=True)
        self.ip = ip
        self.ports = ports
        self.interval = max(0.1, interval)
        self.timeline = timeline
        self.run_dir = run
        self.stop_event = stop_event
        self.last: dict[int, bool] = {}
        self.sample_path = run / "network.jsonl"
        self.arp_path = run / "arp.jsonl"
        self._last_arp: str | None = None
        self._last_arp_at = 0.0

    def _arp(self):
        now = time.monotonic()
        if now - self._last_arp_at < 2.0:
            return
        self._last_arp_at = now
        if os.name == "nt":
            rc, out, err = run_command(["arp", "-a", self.ip], timeout=2.0)
        else:
            rc, out, err = run_command(["ip", "neigh", "show", self.ip], timeout=2.0)
        text = out.strip()
        mac = None
        state = None
        if text:
            m = re.search(r"([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})", text, re.I)
            if m:
                mac = m.group(1).lower().replace("-", ":")
            if os.name != "nt":
                parts = text.split()
                state = parts[-1] if parts else None
        present = bool(text and self.ip in text)
        append_jsonl(self.arp_path, {"t": round(now, 6), "ip": self.ip, "present": present, "mac": mac, "state": state, "rc": rc})
        key = f"{present}:{mac}:{state}"
        if key != self._last_arp:
            self.timeline.emit("arp", "NEIGHBOR_CHANGE", ip=self.ip, present=present, mac=mac, state=state)
            self._last_arp = key

    def run(self):
        self.timeline.emit("network", "PROBE_START", ip=self.ip, ports=self.ports, interval=self.interval)
        while not self.stop_event.is_set():
            loop_start = time.monotonic()
            for port in self.ports:
                result = tcp_probe(self.ip, port, timeout=min(0.5, self.interval))
                sample = {"t_mono": round(time.monotonic(), 6), "ip": self.ip, **result}
                append_jsonl(self.sample_path, sample)
                current = bool(result.get("open"))
                previous = self.last.get(port)
                if previous is None:
                    self.timeline.emit(
                        "tcp",
                        "PORT_BASELINE",
                        ip=self.ip,
                        port=port,
                        open=current,
                        elapsed_ms=result.get("elapsed_ms"),
                        error=result.get("error"),
                    )
                    self.last[port] = current
                elif previous != current:
                    self.timeline.emit(
                        "tcp",
                        "PORT_UP" if current else "PORT_DOWN",
                        ip=self.ip,
                        port=port,
                        elapsed_ms=result.get("elapsed_ms"),
                        error=result.get("error"),
                    )
                    self.last[port] = current
            self._arp()
            spent = time.monotonic() - loop_start
            self.stop_event.wait(max(0.01, self.interval - spent))
        self.timeline.emit("network", "PROBE_STOP")
