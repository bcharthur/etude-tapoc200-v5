from __future__ import annotations

import threading
from pathlib import Path

from .common import append_jsonl, monotonic, utc_now_iso


class Timeline:
    def __init__(self, path: Path, start_mono: float):
        self.path = path
        self.start_mono = start_mono
        self._lock = threading.Lock()

    def emit(self, source: str, event: str, **fields) -> dict:
        obj = {
            "t": round(monotonic() - self.start_mono, 6),
            "utc": utc_now_iso(),
            "source": source,
            "event": event,
            **fields,
        }
        with self._lock:
            append_jsonl(self.path, obj)
        return obj
