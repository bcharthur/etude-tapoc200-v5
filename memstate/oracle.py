from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .network import tcp_probe
from .scope import load_scope


def watch_crash(
    *,
    seconds: int,
    interval: float,
    out_path: str,
    ports=(443,554,2020,8800),
    verbose: bool = True,
):
    scope = load_scope()
    ip = scope.target_ip
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    previous_up = None
    first_down = None
    first_up_after_down = None
    rows = 0
    last_heartbeat = 0.0

    if verbose:
        print(
            f"[crash-oracle] watching scoped target {ip} for {seconds}s "
            f"(ports {','.join(str(p) for p in ports)})",
            flush=True,
        )

    with out.open("w", encoding="utf-8") as f:
        while time.time() - started < seconds:
            probes = {
                str(p): tcp_probe(ip, p, timeout=min(0.35, max(interval, 0.1)))
                for p in ports
            }
            up = any(v["open"] for v in probes.values())
            now = time.time()
            ts = datetime.now(timezone.utc).isoformat()

            event = None
            if previous_up is not None and up != previous_up:
                event = "TARGET_UP" if up else "TARGET_DOWN"

            if not up and first_down is None:
                first_down = ts
            if up and first_down and first_up_after_down is None:
                first_up_after_down = ts

            row = {
                "ts": ts,
                "target_ip": ip,
                "up": up,
                "event": event,
                "ports": probes,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush()

            if verbose and (
                rows == 0
                or event is not None
                or now - last_heartbeat >= 10
            ):
                open_ports = [
                    p for p, v in probes.items() if v["open"]
                ]
                print(
                    f"[crash-oracle] {ts} "
                    f"{'UP' if up else 'DOWN'} "
                    f"open={open_ports or 'none'}"
                    + (f" EVENT={event}" if event else ""),
                    flush=True,
                )
                last_heartbeat = now

            previous_up = up
            rows += 1
            time.sleep(interval)

    return {
        "target_ip": ip,
        "rows": rows,
        "output": str(out),
        "first_down": first_down,
        "first_up_after_down": first_up_after_down,
    }
