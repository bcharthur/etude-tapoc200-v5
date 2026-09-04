from __future__ import annotations

import threading
from pathlib import Path

from memstate.evidence import write_json
from memstate.network import snapshot


class StateSampler(threading.Thread):
    def __init__(self, *, ip: str, interval: float, timeline, run: Path, stop_event: threading.Event):
        super().__init__(name="observer-state", daemon=True)
        self.ip = ip
        self.interval = max(2.0, interval)
        self.timeline = timeline
        self.run_dir = run
        self.stop_event = stop_event

    @staticmethod
    def summarize(obj: dict) -> dict:
        tcp = obj.get("tcp", {}) if isinstance(obj, dict) else {}
        return {
            "tcp_open": sorted(int(p) for p, v in tcp.items() if isinstance(v, dict) and v.get("open")),
            "https_status": (obj.get("https_discover") or {}).get("status_line") if isinstance(obj, dict) else None,
            "tdp_available": (obj.get("tdp_decrypt") or {}).get("available") if isinstance(obj, dict) else None,
        }

    def run(self):
        seq = 0
        self.timeline.emit("state", "SAMPLER_START", interval=self.interval)
        while not self.stop_event.is_set():
            try:
                obj = snapshot(self.ip)
                write_json(self.run_dir / "state-samples" / f"{seq:04d}.json", obj)
                self.timeline.emit("state", "SNAPSHOT", seq=seq, **self.summarize(obj))
            except Exception as exc:
                self.timeline.emit("state", "SNAPSHOT_ERROR", seq=seq, error=f"{type(exc).__name__}: {exc}")
            seq += 1
            self.stop_event.wait(self.interval)
        self.timeline.emit("state", "SAMPLER_STOP", samples=seq)
