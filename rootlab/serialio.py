from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def list_ports():
    try:
        from serial.tools import list_ports as lp
    except ImportError as exc:
        raise RuntimeError(
            "pyserial missing. Run: pip install -r requirements-rootlab.txt"
        ) from exc

    return [
        {
            "device": p.device,
            "description": p.description,
            "hwid": p.hwid,
            "vid": p.vid,
            "pid": p.pid,
        }
        for p in lp.comports()
    ]


def miniterm(port: str, baud: int):
    ports = {p["device"] for p in list_ports()}
    if port not in ports:
        raise RuntimeError(f"{port} not found. Present: {sorted(ports)}")
    return subprocess.call([
        sys.executable, "-m", "serial.tools.miniterm",
        port, str(baud),
    ])


def capture(port: str, baud: int, seconds: int, output: str):
    try:
        import serial
    except ImportError as exc:
        raise RuntimeError(
            "pyserial missing. Run: pip install -r requirements-rootlab.txt"
        ) from exc

    ports = {p["device"] for p in list_ports()}
    if port not in ports:
        raise RuntimeError(f"{port} not found. Present: {sorted(ports)}")

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    raw_path = out.with_suffix(out.suffix + ".bin")

    started = time.time()
    lines = 0
    with serial.Serial(port, baud, timeout=0.2) as ser, \
         out.open("w", encoding="utf-8") as text, \
         raw_path.open("wb") as raw:
        buf = bytearray()
        while time.time() - started < seconds:
            chunk = ser.read(4096)
            if not chunk:
                continue
            raw.write(chunk)
            raw.flush()
            buf.extend(chunk)
            while b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = bytearray(rest)
                row = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "text": line.rstrip(b"\r").decode("utf-8", errors="replace"),
                }
                text.write(json.dumps(row, ensure_ascii=False) + "\n")
                text.flush()
                lines += 1

    return {
        "port": port,
        "baud": baud,
        "seconds": seconds,
        "text_log": str(out),
        "raw_log": str(raw_path),
        "line_count": lines,
    }
