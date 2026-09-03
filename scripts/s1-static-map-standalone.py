#!/usr/bin/env python3
"""Standalone entrypoint for the S1 static mapper.

This mirrors V5PatchLab v1.0.15's `s1-static-map` command without importing the
rest of the firmware/cloud tooling. It is intended for repository-level
reproducibility of the static RF/onboarding map.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from v5patchlab.s1map import build_report, write_report


def main() -> int:
    p = argparse.ArgumentParser(description="C200 V5 S1 static RF/onboarding mapper")
    p.add_argument("main", help="Recovered C200 V5 main ELF")
    p.add_argument("--rootfs", default=None, help="Extracted SquashFS root")
    p.add_argument("--xrefs", action="store_true", help="Generate approximate MIPS string xrefs")
    p.add_argument("--out", default="analysis/s1-static-map", help="Output directory")
    a = p.parse_args()

    report = build_report(a.main, a.rootfs, xrefs=a.xrefs)
    outputs = write_report(report, a.out)
    result = {"report": report, "outputs": outputs}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
