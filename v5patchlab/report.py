from __future__ import annotations

import json
from pathlib import Path

from .diff import compare
from .elfmap import approximate_xrefs, elf_info
from .evidence import write_json
from .versions import CVE_SEEDS


def _safe_xrefs(path, seeds):
    try:
        return approximate_xrefs(path, seeds)
    except Exception as exc:
        return {
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
        }


def build_report(
    old_main: str | Path,
    new_main: str | Path,
    out_dir: str | Path,
):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    d = compare(old_main, new_main)

    xrefs = {}
    for cve, meta in CVE_SEEDS.items():
        xrefs[cve] = {
            "old": _safe_xrefs(old_main, meta["themes"]),
            "new": _safe_xrefs(new_main, meta["themes"]),
        }

    result = {
        "diff": d,
        "cve_xrefs": xrefs,
        "interpretation": {
            "CVE-2026-15315": (
                "Prioritize code around challenge/session verification and "
                "device_confirm/dev_confirm related strings. Look for newly "
                "added equality/freshness/length validation in 1.4.6."
            ),
            "CVE-2026-15316": (
                "Prioritize configuration-service paths that decode/handle "
                "ciphertext and credentials. Look for new upper bounds before "
                "base64/RSA/decrypt/allocation/copy operations and new "
                "exception/error paths in 1.4.6."
            ),
        },
    }

    write_json(out / "patch-report.json", result)

    lines = [
        "# C200 V5 1.4.4 → 1.4.6 patch-diff report",
        "",
        f"- old: `{old_main}`",
        f"- new: `{new_main}`",
        f"- old SHA256: `{d['old']['sha256']}`",
        f"- new SHA256: `{d['new']['sha256']}`",
        f"- sizes: {d['old']['size']} → {d['new']['size']}",
        f"- changed byte-runs (raw positional heuristic): {d['changed_run_count']}",
        "",
        "## CVE focus",
        "",
    ]

    for cve, meta in CVE_SEEDS.items():
        lines += [
            f"### {cve} — {meta['title']}",
            "",
            meta["reason"],
            "",
            "High-value string/xref seeds:",
            "",
            "```text",
            " ".join(meta["themes"]),
            "```",
            "",
            (
                f"Old xref analysis: "
                f"{'OK' if 'error' not in xrefs[cve]['old'] else xrefs[cve]['old']['error']}"
            ),
            (
                f"New xref analysis: "
                f"{'OK' if 'error' not in xrefs[cve]['new'] else xrefs[cve]['new']['error']}"
            ),
            "",
        ]

    lines += [
        "## How to use this in Ghidra",
        "",
        "1. Import both `main` binaries as MIPS little-endian ELF.",
        "2. Search the seed strings above in both builds.",
        "3. Use xrefs from `patch-report.json` as navigation seeds.",
        "4. Compare callers around challenge/session verification for 15315.",
        "5. Compare decode/allocation/copy/error paths around encrypted credential handling for 15316.",
        "6. Do not infer vulnerability from a changed string alone; verify actual data-flow and bounds.",
        "",
        "## Important limitation",
        "",
        "Raw positional byte-runs are only a heuristic. Compiler/linker layout changes can shift code.",
        "The MIPS xref layer is also approximate; Ghidra remains the source of truth for control/data flow.",
    ]

    (out / "patch-report.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return result
