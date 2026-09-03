from __future__ import annotations

import csv
import math
from collections import Counter
from pathlib import Path

from .evidence import sha256_file, write_json
from .partitions import load_partition_map, partition_for_offset


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def printable_preview(buf: bytes, limit=96) -> str:
    out = []
    for b in buf[:limit]:
        out.append(chr(b) if 32 <= b <= 126 else ".")
    return "".join(out)


def carve_flash(dump_path: str, out_dir: str, map_path: str):
    dump = Path(dump_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    meta, parts = load_partition_map(map_path)
    data = dump.read_bytes()

    result = {
        "input": str(dump),
        "input_size": len(data),
        "input_sha256": sha256_file(dump),
        "expected_flash_size": meta.get("flash_size"),
        "size_matches": len(data) == meta.get("flash_size"),
        "partitions": [],
    }

    for p in parts:
        chunk = data[p.start:p.end]
        target = out / f"{p.start:08x}-{p.end:08x}_{p.name}.bin"
        target.write_bytes(chunk)
        result["partitions"].append({
            "name": p.name,
            "start": p.start,
            "end": p.end,
            "size": len(chunk),
            "sha256": sha256_file(target),
            "path": str(target),
        })

    write_json(out / "carve-manifest.json", result)
    return result


def changed_runs(a: bytes, b: bytes):
    n = min(len(a), len(b))
    runs = []
    start = None

    for i in range(n):
        diff = a[i] != b[i]
        if diff and start is None:
            start = i
        elif not diff and start is not None:
            runs.append((start, i))
            start = None

    if start is not None:
        runs.append((start, n))

    if len(a) != len(b):
        runs.append((n, max(len(a), len(b))))

    return runs


def flash_diff(
    before_path: str,
    after_path: str,
    out_dir: str,
    map_path: str,
    *,
    page_size: int = 4096,
    preview_bytes: int = 64,
):
    before_p = Path(before_path)
    after_p = Path(after_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    a = before_p.read_bytes()
    b = after_p.read_bytes()
    meta, parts = load_partition_map(map_path)

    runs = changed_runs(a, b)

    partition_stats = {}
    for p in parts:
        aa = a[p.start:p.end]
        bb = b[p.start:p.end]
        n = min(len(aa), len(bb))
        changed = sum(1 for i in range(n) if aa[i] != bb[i])
        partition_stats[p.name] = {
            "start": p.start,
            "end": p.end,
            "size": p.size,
            "changed_bytes": changed,
            "changed_percent": round((changed / p.size * 100) if p.size else 0, 6),
            "before_entropy": round(entropy(aa), 5),
            "after_entropy": round(entropy(bb), 5),
        }

    run_rows = []
    for idx, (start, end) in enumerate(runs):
        p = partition_for_offset(start, parts)
        aa = a[start:min(end, start + preview_bytes)]
        bb = b[start:min(end, start + preview_bytes)]

        ctx_start = max(0, start - 32)
        ctx_end = min(len(a), end + 32)

        run_rows.append({
            "index": idx,
            "start": start,
            "end": end,
            "length": end - start,
            "partition": p.name if p else None,
            "partition_offset": start - p.start if p else None,
            "before_hex": aa.hex(),
            "after_hex": bb.hex(),
            "before_ascii": printable_preview(a[ctx_start:ctx_end]),
            "after_ascii": printable_preview(b[ctx_start:ctx_end]),
            "before_all_zero": bool(aa) and set(aa) == {0},
            "after_all_zero": bool(bb) and set(bb) == {0},
            "before_all_ff": bool(aa) and set(aa) == {255},
            "after_all_ff": bool(bb) and set(bb) == {255},
        })

    pages = []
    n = min(len(a), len(b))
    for start in range(0, n, page_size):
        end = min(n, start + page_size)
        changed = sum(
            1 for i in range(start, end)
            if a[i] != b[i]
        )
        if changed:
            p = partition_for_offset(start, parts)
            pages.append({
                "page_start": start,
                "page_end": end,
                "partition": p.name if p else None,
                "changed_bytes": changed,
                "changed_percent": round(changed / (end-start) * 100, 4),
                "before_entropy": round(entropy(a[start:end]), 5),
                "after_entropy": round(entropy(b[start:end]), 5),
            })

    summary = {
        "before": {
            "path": str(before_p),
            "size": len(a),
            "sha256": sha256_file(before_p),
        },
        "after": {
            "path": str(after_p),
            "size": len(b),
            "sha256": sha256_file(after_p),
        },
        "partition_map": str(map_path),
        "expected_flash_size": meta.get("flash_size"),
        "same_size": len(a) == len(b),
        "changed_run_count": len(runs),
        "changed_byte_count": sum(
            1 for i in range(min(len(a), len(b)))
            if a[i] != b[i]
        ) + abs(len(a)-len(b)),
        "partition_stats": partition_stats,
        "changed_pages": pages,
        "interesting_runs": sorted(
            run_rows,
            key=lambda x: x["length"],
            reverse=True,
        )[:500],
    }

    write_json(out / "flash-diff.json", summary)

    with (out / "changed-runs.csv").open("w", newline="", encoding="utf-8") as f:
        cols = [
            "index","start","end","length","partition","partition_offset",
            "before_hex","after_hex","before_ascii","after_ascii",
            "before_all_zero","after_all_zero","before_all_ff","after_all_ff"
        ]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(run_rows)

    with (out / "changed-pages.csv").open("w", newline="", encoding="utf-8") as f:
        cols = [
            "page_start","page_end","partition","changed_bytes",
            "changed_percent","before_entropy","after_entropy"
        ]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(pages)

    return summary
