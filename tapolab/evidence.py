from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "evidence" / "runs"


def new_run_dir() -> Path:
    p = RUNS / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    p.mkdir(parents=True, exist_ok=False)
    return p


def write_json(path: Path, data):
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(run_dir: Path, extra=None) -> dict:
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "files": {},
    }
    for p in sorted(run_dir.iterdir()):
        if p.is_file():
            manifest["files"][p.name] = {
                "sha256": sha256_file(p),
                "size": p.stat().st_size,
            }
    if extra:
        manifest.update(extra)
    return manifest
