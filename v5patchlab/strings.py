from __future__ import annotations

import re
from pathlib import Path


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_strings(data: bytes) -> list[tuple[int, str]]:
    out = []
    for m in ASCII_RE.finditer(data):
        out.append((m.start(), m.group().decode("ascii", errors="replace")))
    return out


def index(path: str | Path, seeds: list[str]) -> dict:
    p = Path(path)
    data = p.read_bytes()
    strings = extract_strings(data)

    hits = {}
    lower_seeds = [s.lower() for s in seeds]

    for seed, lseed in zip(seeds, lower_seeds):
        rows = []
        for off, s in strings:
            if lseed in s.lower():
                rows.append({
                    "offset": off,
                    "string": s[:1000],
                })
                if len(rows) >= 100:
                    break
        if rows:
            hits[seed] = rows

    return {
        "path": str(p),
        "string_count": len(strings),
        "hits": hits,
    }


def string_delta(old_path: str | Path, new_path: str | Path) -> dict:
    old = {s for _, s in extract_strings(Path(old_path).read_bytes())}
    new = {s for _, s in extract_strings(Path(new_path).read_bytes())}

    added = sorted(new - old)
    removed = sorted(old - new)

    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added[:5000],
        "removed": removed[:5000],
    }
