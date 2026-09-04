from __future__ import annotations

import threading
import time
from pathlib import Path

from .common import append_jsonl, redact_url, sanitize_text


class RtspProbe(threading.Thread):
    def __init__(self, *, url: str | None, timeline, run: Path, stop_event: threading.Event, heartbeat: float = 5.0):
        super().__init__(name="observer-rtsp", daemon=True)
        self.url = url
        self.timeline = timeline
        self.run_dir = run
        self.stop_event = stop_event
        self.heartbeat = max(1.0, heartbeat)
        self.sample_path = run / "rtsp.jsonl"

    def run(self):
        if not self.url:
            self.timeline.emit("rtsp", "DISABLED", reason="no TAPO_RTSP_URL or TAPO_RTSP_USER/TAPO_RTSP_PASSWORD")
            return
        try:
            import cv2  # type: ignore
        except Exception as exc:
            self.timeline.emit("rtsp", "DISABLED", reason=f"opencv unavailable: {type(exc).__name__}")
            return

        safe_url = redact_url(self.url)
        self.timeline.emit("rtsp", "PROBE_START", url=safe_url)
        cap = None
        connected = False
        frames = 0
        connect_attempt = 0
        last_heartbeat = 0.0
        last_frame = None

        while not self.stop_event.is_set():
            if cap is None:
                connect_attempt += 1
                t0 = time.monotonic()
                try:
                    cap = cv2.VideoCapture(self.url, cv2.CAP_FFMPEG)
                    # Supported by recent OpenCV/FFmpeg builds; harmless if ignored.
                    try:
                        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 1500)
                        cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 1500)
                    except Exception:
                        pass
                    ok = bool(cap.isOpened())
                except Exception as exc:
                    ok = False
                    append_jsonl(self.sample_path, {"event": "OPEN_EXCEPTION", "error": sanitize_text(exc)})
                elapsed = round((time.monotonic() - t0) * 1000.0, 2)
                if not ok:
                    if cap is not None:
                        try:
                            cap.release()
                        except Exception:
                            pass
                    cap = None
                    if connected:
                        connected = False
                    self.timeline.emit("rtsp", "OPEN_FAILED", attempt=connect_attempt, elapsed_ms=elapsed)
                    self.stop_event.wait(1.0)
                    continue
                connected = True
                self.timeline.emit("rtsp", "CONNECTED", attempt=connect_attempt, elapsed_ms=elapsed)
                last_heartbeat = time.monotonic()

            try:
                ok, _frame = cap.read()
            except Exception as exc:
                ok = False
                append_jsonl(self.sample_path, {"event": "READ_EXCEPTION", "error": sanitize_text(exc)})
            now = time.monotonic()
            if ok:
                frames += 1
                last_frame = now
                if now - last_heartbeat >= self.heartbeat:
                    append_jsonl(self.sample_path, {"event": "FRAME_HEARTBEAT", "frames": frames, "last_frame_mono": last_frame})
                    self.timeline.emit("rtsp", "FRAME_HEARTBEAT", frames=frames)
                    last_heartbeat = now
            else:
                if connected:
                    self.timeline.emit("rtsp", "DISCONNECTED", frames=frames)
                connected = False
                try:
                    cap.release()
                except Exception:
                    pass
                cap = None
                self.stop_event.wait(0.5)

        if cap is not None:
            try:
                cap.release()
            except Exception:
                pass
        self.timeline.emit("rtsp", "PROBE_STOP", frames=frames)
