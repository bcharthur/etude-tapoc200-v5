from __future__ import annotations

import re
from pathlib import Path


IOMEM_RE = re.compile(
    r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+?)\s*$"
)


def system_ram_ranges(path: str | Path):
    ranges = []
    for line in Path(path).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        m = IOMEM_RE.match(line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        label = m.group(3)
        if label.strip().lower() == "system ram":
            ranges.append({
                "start": start,
                "end_inclusive": end,
                "length": end - start + 1,
                "label": label,
            })
    return ranges


def generate_ram_script(
    iomem: str | Path,
    output: str | Path,
    destination: str = "/mnt/sd/rootlab-ram",
):
    ranges = system_ram_ranges(iomem)
    if not ranges:
        raise RuntimeError("No exact 'System RAM' ranges found in iomem file")

    lines = [
        "#!/bin/sh",
        "set -eu",
        f"OUT='{destination}'",
        'mkdir -p "$OUT"',
        'test -r /dev/mem || { echo "/dev/mem not readable"; exit 2; }',
        'echo "Dumping only ranges labelled exactly System RAM in /proc/iomem"',
    ]

    for i, r in enumerate(ranges):
        start = r["start"]
        length = r["length"]
        # bs=4096 when aligned, otherwise use 1-byte first/last ranges would be slow.
        # Most embedded System RAM ranges are page aligned; refuse unsafe approximation.
        if start % 4096 != 0 or length % 4096 != 0:
            lines.append(
                f'echo "SKIP unaligned RAM range 0x{start:x} length 0x{length:x}"'
            )
            continue
        skip = start // 4096
        count = length // 4096
        name = f"system-ram-{i:02d}-0x{start:08x}-0x{r['end_inclusive']:08x}.bin"
        lines.append(
            f'dd if=/dev/mem of="$OUT/{name}" bs=4096 '
            f'skip={skip} count={count} 2>"$OUT/{name}.dd.log"'
        )
        lines.append("sync")

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "iomem": str(iomem),
        "output": str(out),
        "ranges": ranges,
        "note": "Script refuses unaligned ranges and never reads non-System-RAM labels.",
    }
