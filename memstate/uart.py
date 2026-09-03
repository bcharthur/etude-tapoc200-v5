from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = {
    "kernel_oops": re.compile(r"\bOops\b|Kernel panic|BUG:|Unable to handle", re.I),
    "watchdog": re.compile(r"watchdog|wdt", re.I),
    "reboot": re.compile(r"reboot|restart|resetting system|machine restart", re.I),
    "factory": re.compile(r"factory|default|unbind|provision|pairing|softap", re.I),
    "mtd": re.compile(r"\bmtd\b|jffs2|squashfs|erase|flash", re.I),
}

REGEX_REGS = {
    "epc": re.compile(r"\bEPC\b\s*[:=]?\s*(0x)?([0-9a-fA-F]{6,16})"),
    "ra": re.compile(r"\bRA\b\s*[:=]?\s*(0x)?([0-9a-fA-F]{6,16})"),
    "sp": re.compile(r"\bSP\b\s*[:=]?\s*(0x)?([0-9a-fA-F]{6,16})"),
    "badva": re.compile(r"\bBadVA\b\s*[:=]?\s*(0x)?([0-9a-fA-F]{6,16})", re.I),
    "cause": re.compile(r"\bCause\b\s*[:=]?\s*(0x)?([0-9a-fA-F]{2,16})", re.I),
}


def list_serial_ports():
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        raise RuntimeError("Install pyserial: pip install pyserial") from exc

    rows = []
    for p in list_ports.comports():
        rows.append({
            "device": p.device,
            "description": p.description,
            "hwid": p.hwid,
            "vid": p.vid,
            "pid": p.pid,
            "serial_number": p.serial_number,
        })
    return rows


def capture_uart(port: str, baud: int, seconds: int, out_path: str):
    try:
        import serial
    except ImportError as exc:
        raise RuntimeError("Install pyserial: pip install pyserial") from exc

    available = {x["device"] for x in list_serial_ports()}
    if port not in available:
        raise RuntimeError(
            f"Serial port {port!r} is not present. Detected ports: "
            f"{sorted(available) if available else 'none'}. "
            "Connect the USB-to-TTL adapter first, then run "
            "`python .\\memorylab.py uart-ports`."
        )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    lines = 0

    with serial.Serial(
        port=port,
        baudrate=baud,
        timeout=0.25,
        bytesize=8,
        parity="N",
        stopbits=1,
    ) as ser, out.open("w", encoding="utf-8", errors="replace") as f:
        buf = bytearray()

        while time.time() - started < seconds:
            chunk = ser.read(4096)
            if not chunk:
                continue
            buf.extend(chunk)

            while b"\n" in buf:
                raw, _, rest = buf.partition(b"\n")
                buf = bytearray(rest)
                text = raw.rstrip(b"\r").decode("utf-8", errors="replace")
                ts = datetime.now(timezone.utc).isoformat()
                f.write(json.dumps({
                    "ts": ts,
                    "text": text,
                }, ensure_ascii=False) + "\n")
                f.flush()
                lines += 1

        if buf:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(json.dumps({
                "ts": ts,
                "text": bytes(buf).decode("utf-8", errors="replace"),
            }, ensure_ascii=False) + "\n")
            lines += 1

    return {
        "port": port,
        "baud": baud,
        "seconds": seconds,
        "output": str(out),
        "line_count": lines,
    }


def analyze_uart(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"UART log does not exist: {p}")

    events = []
    registers = {}

    for idx, line in enumerate(
        p.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        try:
            obj = json.loads(line)
            text = str(obj.get("text", ""))
            ts = obj.get("ts")
        except Exception:
            text = line
            ts = None

        kinds = [
            name for name, rx in PATTERNS.items()
            if rx.search(text)
        ]

        found_regs = {}
        for name, rx in REGEX_REGS.items():
            m = rx.search(text)
            if m:
                try:
                    found_regs[name] = int(m.group(2), 16)
                    registers[name] = found_regs[name]
                except Exception:
                    pass

        if kinds or found_regs:
            events.append({
                "line": idx,
                "ts": ts,
                "kinds": kinds,
                "registers": {
                    k: {"value": v, "hex": hex(v)}
                    for k, v in found_regs.items()
                },
                "text": text,
            })

    return {
        "path": str(p),
        "classification": {
            "kernel_oops_seen": any("kernel_oops" in e["kinds"] for e in events),
            "watchdog_seen": any("watchdog" in e["kinds"] for e in events),
            "reboot_seen": any("reboot" in e["kinds"] for e in events),
            "factory_state_terms_seen": any("factory" in e["kinds"] for e in events),
            "flash_terms_seen": any("mtd" in e["kinds"] for e in events),
        },
        "last_registers": {
            k: {"value": v, "hex": hex(v)}
            for k, v in registers.items()
        },
        "events": events,
    }
