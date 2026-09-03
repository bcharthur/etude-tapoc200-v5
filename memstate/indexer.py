from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path

from .evidence import sha256_file, write_json


KEYWORD_GROUPS = {
    "state_reset": [
        "factory_reset", "factory reset", "factory_default", "factory default",
        "reset_wifi", "reset wifi", "wifi_reset", "resettofactory",
        "restore_factory", "unbind", "unbound", "binding", "bind_state",
        "configured", "provision", "pairing", "softap", "ap_mode", "ap mode"
    ],
    "reboot_watchdog": [
        "reboot", "watchdog", "/dev/watchdog", "wdt", "restart", "panic",
        "kernel panic", "oops"
    ],
    "flash_config": [
        "/dev/mtd", "mtd", "rootfs_data", "user_record", "factory_info",
        "config", "jffs2", "squashfs", "nvram", "erase", "flash"
    ],
    "network": [
        "/stream", "streamd", "authorization", "rtsp", "onvif",
        "pake_register", "pake_share", "default_userpw", "userpw",
        "device_confirm", "key-exchange", "encrypt_type", "tdp"
    ],
    "dangerous_api": [
        "strcpy", "strcat", "sprintf", "vsprintf", "memcpy", "memmove",
        "system", "popen", "ioctl", "execve"
    ],
}


def _ascii_strings(data: bytes, min_len=4):
    start = None
    for i, b in enumerate(data):
        printable = 32 <= b <= 126
        if printable and start is None:
            start = i
        elif not printable and start is not None:
            if i - start >= min_len:
                yield start, data[start:i].decode("ascii", errors="replace")
            start = None
    if start is not None and len(data) - start >= min_len:
        yield start, data[start:].decode("ascii", errors="replace")


def firmware_index(root_dir: str, out_dir: str, *, max_file_size=64*1024*1024):
    root = Path(root_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    hits = []
    files = []

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue

        rel = str(p.relative_to(root))
        row = {
            "path": rel,
            "size": size,
            "sha256": None,
            "scanned": False,
            "hit_count": 0,
        }

        if size <= max_file_size:
            try:
                data = p.read_bytes()
                row["sha256"] = hashlib.sha256(data).hexdigest()
                row["scanned"] = True

                file_hits = 0
                for offset, s in _ascii_strings(data):
                    lower = s.lower()
                    for group, keywords in KEYWORD_GROUPS.items():
                        matched = [kw for kw in keywords if kw.lower() in lower]
                        if not matched:
                            continue
                        hits.append({
                            "file": rel,
                            "offset": offset,
                            "offset_hex": hex(offset),
                            "group": group,
                            "matched": matched,
                            "string": s[:500],
                        })
                        file_hits += 1

                row["hit_count"] = file_hits

            except Exception as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"

        files.append(row)

    result = {
        "root": str(root),
        "keyword_groups": KEYWORD_GROUPS,
        "file_count": len(files),
        "hit_count": len(hits),
        "files": files,
        "hits": hits,
    }

    write_json(out / "firmware-index.json", result)

    with (out / "firmware-hits.csv").open("w", newline="", encoding="utf-8") as f:
        cols = ["file","offset","offset_hex","group","matched","string"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for h in hits:
            row = dict(h)
            row["matched"] = ";".join(row["matched"])
            w.writerow(row)

    return result


def directory_diff(before_dir: str, after_dir: str, out_dir: str):
    aroot = Path(before_dir)
    broot = Path(after_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    def inventory(root):
        inv = {}
        for p in root.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(root))
                try:
                    inv[rel] = {
                        "size": p.stat().st_size,
                        "sha256": sha256_file(p),
                    }
                except Exception as exc:
                    inv[rel] = {"error": str(exc)}
        return inv

    a = inventory(aroot)
    b = inventory(broot)
    names = sorted(set(a) | set(b))

    rows = []
    for name in names:
        if name not in a:
            status = "added"
        elif name not in b:
            status = "removed"
        elif a[name].get("sha256") != b[name].get("sha256"):
            status = "modified"
        else:
            status = "same"

        if status != "same":
            rows.append({
                "path": name,
                "status": status,
                "before": a.get(name),
                "after": b.get(name),
            })

    result = {
        "before": str(aroot),
        "after": str(broot),
        "changed_entry_count": len(rows),
        "entries": rows,
    }
    write_json(out / "directory-diff.json", result)
    return result
