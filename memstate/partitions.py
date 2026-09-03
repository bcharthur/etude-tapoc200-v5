from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Partition:
    name: str
    start: int
    end: int

    @property
    def size(self):
        return self.end - self.start


def load_partition_map(path: str | Path = "config/c200v5_partitions.json"):
    p = Path(path)
    obj = json.loads(p.read_text(encoding="utf-8"))
    parts = [
        Partition(x["name"], int(x["start"]), int(x["end"]))
        for x in obj["partitions"]
    ]
    return obj, parts


def partition_for_offset(offset: int, parts: list[Partition]):
    for p in parts:
        if p.start <= offset < p.end:
            return p
    return None
