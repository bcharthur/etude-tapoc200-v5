from __future__ import annotations

import json
from pathlib import Path


def _load(path):
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def _snapshot_has_reachable_surface(obj: dict) -> bool:
    quality = obj.get("snapshot_quality")
    if isinstance(quality, dict) and "any_service_open" in quality:
        return bool(quality.get("any_service_open"))

    tcp = obj.get("tcp")
    if not isinstance(tcp, dict):
        return False

    return any(
        isinstance(v, dict) and v.get("open") is True
        for v in tcp.values()
    )


def find_latest_state(
    label: str,
    base: str = "evidence/runs",
    *,
    require_reachable: bool = True,
) -> Path:
    base_p = Path(base)
    matches = sorted(
        base_p.glob(f"*/state-{label}.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not matches:
        raise FileNotFoundError(
            f"No state-{label}.json found under {base_p}."
        )

    if not require_reachable:
        return matches[0]

    rejected = []

    for p in matches:
        try:
            obj = _load(p)
        except Exception as exc:
            rejected.append({
                "path": str(p),
                "reason": f"parse error: {type(exc).__name__}: {exc}",
            })
            continue

        if _snapshot_has_reachable_surface(obj):
            return p

        rejected.append({
            "path": str(p),
            "reason": "no tested TCP service reachable",
        })

    raise RuntimeError(
        f"Found state-{label} snapshots, but none has a reachable tested "
        f"surface. Rejected: {rejected}"
    )


def build_state_report(normal_path: str, setup_path: str, output: str):
    n = _load(normal_path)
    s = _load(setup_path)

    def val(obj, *path):
        cur = obj
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur

    lines = [
        "# C200 V5 — NORMAL vs SETUP state map",
        "",
        f"- NORMAL source: `{normal_path}`",
        f"- SETUP source: `{setup_path}`",
        "",
        "| Surface | NORMAL | SETUP |",
        "|---|---|---|",
    ]

    for port in ("80", "443", "554", "2020", "8800"):
        nn = val(n, "tcp", port, "open")
        ss = val(s, "tcp", port, "open")
        lines.append(f"| TCP/{port} | {nn} | {ss} |")

    npake = val(n, "https_discover", "json", "result", "tpap", "pake")
    spake = val(s, "https_discover", "json", "result", "tpap", "pake")
    lines.append(f"| TPAP pake | `{npake}` | `{spake}` |")

    nnoc = val(n, "https_discover", "json", "result", "tpap", "noc")
    snoc = val(s, "https_discover", "json", "result", "tpap", "noc")
    lines.append(f"| TPAP noc | `{nnoc}` | `{snoc}` |")

    nstream = val(n, "streamd", "status_line")
    sstream = val(s, "streamd", "status_line")
    lines.append(
        f"| Streamd initial status | `{nstream}` | `{sstream}` |"
    )

    nkey = val(n, "streamd", "headers", "key-exchange")
    skey = val(s, "streamd", "headers", "key-exchange")
    lines.append(
        f"| Streamd Key-Exchange | `{nkey}` | `{skey}` |"
    )

    naes = val(n, "tdp_decrypt", "crypto", "aes_material_sha256")
    saes = val(s, "tdp_decrypt", "crypto", "aes_material_sha256")

    lines.extend([
        "",
        "## TDP state",
        "",
        f"- NORMAL AES-material SHA-256: `{naes}`",
        f"- SETUP AES-material SHA-256: `{saes}`",
        f"- Same material: `{bool(naes and saes and naes == saes)}`",
        "",
        "## Interpretation",
        "",
        "Use this as a state oracle and correlate it with:",
        "",
        "- UART reset/reboot logs;",
        "- SPI NOR changed offsets/pages;",
        "- Ghidra xrefs to config/reset/provisioning writers.",
    ])

    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "output": output,
        "normal": normal_path,
        "setup": setup_path,
    }
