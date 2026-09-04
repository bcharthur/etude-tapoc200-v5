from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .common import append_jsonl, sanitize_text


class TapoProbe(threading.Thread):
    SAFE_METHODS = ("getBasicInfo", "getDeviceInfo")

    def __init__(self, *, ip: str, interval: float, timeline, run: Path, stop_event: threading.Event):
        super().__init__(name="observer-tapo", daemon=True)
        self.ip = ip
        self.interval = max(2.0, interval)
        self.timeline = timeline
        self.run_dir = run
        self.stop_event = stop_event
        self.sample_path = run / "tapo.jsonl"
        self.user = os.getenv("TAPO_USER", "").strip()
        self.password = os.getenv("TAPO_PASSWORD", "").strip()

    def run(self):
        if not self.user or not self.password:
            self.timeline.emit("tapo", "DISABLED", reason="TAPO_USER/TAPO_PASSWORD not set")
            return
        try:
            from pytapo import Tapo  # type: ignore
        except Exception as exc:
            self.timeline.emit("tapo", "DISABLED", reason=f"pytapo unavailable: {type(exc).__name__}")
            return

        secrets = [self.user, self.password]
        self.timeline.emit("tapo", "PROBE_START", interval=self.interval)
        cam = None
        last_ok = None
        method_name = None
        while not self.stop_event.is_set():
            ok = False
            err = None
            result_type = None
            try:
                if cam is None:
                    cam = Tapo(self.ip, self.user, self.password)
                    method_name = next((name for name in self.SAFE_METHODS if callable(getattr(cam, name, None))), None)
                    if method_name is None:
                        raise RuntimeError("No whitelisted non-destructive info method found in installed pytapo")
                result = getattr(cam, method_name)()
                result_type = type(result).__name__
                ok = True
            except Exception as exc:
                err = sanitize_text(f"{type(exc).__name__}: {exc}", secrets)
                cam = None

            append_jsonl(self.sample_path, {"ok": ok, "method": method_name, "result_type": result_type, "error": err})
            if last_ok is None or last_ok != ok:
                self.timeline.emit("tapo", "API_UP" if ok else "API_DOWN", method=method_name, error=err)
                last_ok = ok
            self.stop_event.wait(self.interval)
        self.timeline.emit("tapo", "PROBE_STOP")
