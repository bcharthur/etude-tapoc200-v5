from __future__ import annotations

from pathlib import Path
import re


MAP_RE = re.compile(
    r"^(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)\s+"
    r"(?P<perms>[-rwxps]+)\s+\S+\s+\S+\s+\S+\s*(?P<path>.*)$"
)


def parse_maps(path: str | Path):
    rows = []
    for line in Path(path).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        m = MAP_RE.match(line.strip())
        if not m:
            continue
        rows.append({
            "start": int(m.group("start"), 16),
            "end": int(m.group("end"), 16),
            "perms": m.group("perms"),
            "path": m.group("path").strip(),
        })
    return rows


def generate_gdb_dump_script(
    maps_path: str | Path,
    output: str | Path,
    *,
    remote: str,
    dump_dir: str,
    writable_only: bool = False,
    max_region: int = 32 * 1024 * 1024,
):
    rows = parse_maps(maps_path)
    selected = []

    for r in rows:
        if "r" not in r["perms"]:
            continue
        if writable_only and "w" not in r["perms"]:
            continue
        size = r["end"] - r["start"]
        if size <= 0 or size > max_region:
            continue
        selected.append(r)

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "set pagination off",
        "set confirm off",
        f"target remote {remote}",
    ]

    for idx, r in enumerate(selected):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", r["path"] or "anon").strip("_")
        safe = safe[-60:] or "anon"
        name = (
            f"{idx:03d}_{r['start']:08x}-{r['end']:08x}_"
            f"{r['perms']}_{safe}.bin"
        )
        target = str(Path(dump_dir) / name).replace("\\", "/")
        lines.append(
            f"dump binary memory {target} "
            f"0x{r['start']:x} 0x{r['end']:x}"
        )

    lines += ["detach", "quit"]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "maps": str(maps_path),
        "output": str(out),
        "remote": remote,
        "selected_regions": len(selected),
        "writable_only": writable_only,
        "max_region": max_region,
    }
