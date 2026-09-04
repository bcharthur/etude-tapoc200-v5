from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_netsh_networks(text: str) -> list[dict]:
    """Parse enough of `netsh wlan show networks mode=bssid` for S1 evidence."""
    rows = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line, re.I)
        if m:
            if current is not None:
                rows.append(current)
            current = {"ssid": m.group(1).strip(), "bssids": []}
            continue
        m = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-f:.-]{12,})", line, re.I)
        if m and current is not None:
            current["bssids"].append(m.group(1).lower().replace("-", ":"))
    if current is not None:
        rows.append(current)
    return rows


def _scan_windows() -> tuple[list[dict], str | None]:
    cp = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if cp.returncode != 0:
        return [], cp.stderr.strip() or cp.stdout.strip()
    return parse_netsh_networks(cp.stdout), None


def observe_softap(
    *,
    seconds: float = 180.0,
    interval: float = 2.0,
    ssid_prefix: str = "Tapo_Cam_",
    out_dir: str | Path = "evidence/s1-rf-observe",
) -> dict:
    if os.name != "nt":
        raise RuntimeError("s1-observe-softap currently uses Windows netsh and must run on Windows.")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / "softap-observation.jsonl"
    start = time.monotonic()
    observations = 0
    hits = []
    errors = []
    last_hit_key = None

    with log_path.open("a", encoding="utf-8") as log:
        while time.monotonic() - start < seconds:
            networks, error = _scan_windows()
            observations += 1
            matching = [x for x in networks if x.get("ssid", "").startswith(ssid_prefix)]
            row = {
                "utc": _utc_now(),
                "elapsed_s": round(time.monotonic() - start, 3),
                "matching": matching,
                "error": error,
            }
            log.write(json.dumps(row, ensure_ascii=False) + "\n")
            log.flush()
            if error:
                errors.append(row)
            if matching:
                key = json.dumps(matching, sort_keys=True)
                if key != last_hit_key:
                    hits.append(row)
                    last_hit_key = key
            time.sleep(max(0.2, interval))

    summary = {
        "platform": platform.platform(),
        "duration_s": seconds,
        "interval_s": interval,
        "ssid_prefix": ssid_prefix,
        "observations": observations,
        "hit_count": len(hits),
        "first_hit": hits[0] if hits else None,
        "last_hit": hits[-1] if hits else None,
        "error_count": len(errors),
        "log": str(log_path),
        "interpretation": (
            "A Tapo_Cam_* observation is evidence of SoftAP/provisioning visibility. "
            "It is not by itself proof of factory reset or loss of binding/configuration."
        ),
    }
    (out / "softap-observation-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary
