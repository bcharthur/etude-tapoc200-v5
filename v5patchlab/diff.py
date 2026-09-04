from __future__ import annotations

import hashlib
from pathlib import Path

from .evidence import sha256_file
from .strings import string_delta, index
from .versions import CVE_SEEDS, COMMON_SECURITY_SEEDS


def byte_runs(a: bytes, b: bytes, merge_gap=16):
    n = min(len(a), len(b))
    raw = []
    start = None

    for i in range(n):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            raw.append([start, i])
            start = None

    if start is not None:
        raw.append([start, n])

    if len(a) != len(b):
        raw.append([n, max(len(a), len(b))])

    merged = []
    for r in raw:
        if not merged or r[0] - merged[-1][1] > merge_gap:
            merged.append(r)
        else:
            merged[-1][1] = r[1]
    return merged


def compare(old_path: str | Path, new_path: str | Path) -> dict:
    old_p = Path(old_path)
    new_p = Path(new_path)
    old = old_p.read_bytes()
    new = new_p.read_bytes()

    runs = byte_runs(old, new)

    seeds = []
    for cve in CVE_SEEDS.values():
        seeds.extend(cve["themes"])
    seeds.extend(COMMON_SECURITY_SEEDS)
    seeds = list(dict.fromkeys(seeds))

    return {
        "old": {
            "path": str(old_p),
            "size": len(old),
            "sha256": sha256_file(old_p),
        },
        "new": {
            "path": str(new_p),
            "size": len(new),
            "sha256": sha256_file(new_p),
        },
        "same_file": old == new,
        "changed_run_count": len(runs),
        "changed_runs": [
            {
                "start": s,
                "end": e,
                "length": e - s,
            }
            for s, e in runs[:10000]
        ],
        "string_delta": string_delta(old_p, new_p),
        "old_seed_index": index(old_p, seeds),
        "new_seed_index": index(new_p, seeds),
    }
