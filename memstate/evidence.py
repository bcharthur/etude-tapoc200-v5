from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def new_run(prefix: str = "memorylab") -> Path:
    base = Path("evidence/runs")
    base.mkdir(parents=True, exist_ok=True)
    p = base / f"{utc_stamp()}-{prefix}"
    i = 1
    while p.exists():
        p = base / f"{utc_stamp()}-{prefix}-{i}"
        i += 1
    p.mkdir(parents=True)
    return p


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def manifest(run: Path, *, tool: str, extra: dict | None = None) -> dict:
    files = []
    for p in sorted(run.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            files.append({
                "path": str(p.relative_to(run)),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })

    obj = {
        "tool": tool,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }
    if extra:
        obj.update(extra)
    return obj
