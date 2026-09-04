from __future__ import annotations

import json
from pathlib import Path

from .evidence import write_json
from .s1controlflow import (
    _iter_symbols,
    _symbol_ranges,
    _load_alloc_sections,
    analyze_function,
    _all_direct_call_sites,
    _owner_function,
    parse_objdump,
)


DEFAULT_ROOT = "onboarding_phy_link_status_change_handle"
DEFAULT_SINKS = (
    "wlan_manager_onboarding_start",
    "onboarding_restart",
    "onboarding_set_start_flag",
    "wlan_manager_ap_get_status",
    "wlan_manager_monitor_get_status",
    "onboarding_ctx_init",
)
CONTEXT_TARGETS = (
    "wlan_manager_start",
    "wlan_manager_onboarding_start",
    "onboarding_restart",
    "is_reonboarding",
    "get_cur_onboarding_mode",
    "wlan_manager_init_reconnect_ctx",
    "wlan_manual_reconnect",
    "wlan_manager_sta_disconnect",
)


def _hex(v):
    return None if v is None else f"0x{int(v):08x}"


def _call_sites(row: dict, target_name: str) -> list[dict]:
    out = []
    for c in row.get("direct_calls", []):
        name = c.get("target_symbol") or c.get("objdump_symbol")
        if name == target_name:
            out.append(c)
    return out


def _instruction_window(disassembly: str, site: int, before: int = 18, after: int = 8) -> list[str]:
    insns = parse_objdump(disassembly)
    idx = next((i for i, ins in enumerate(insns) if ins.address == site), None)
    if idx is None:
        return []
    lo = max(0, idx - before)
    hi = min(len(insns), idx + after + 1)
    return [x.raw for x in insns[lo:hi]]


def _preceding_branches(row: dict, site: int, span: int = 0x90) -> list[dict]:
    out = []
    for b in row.get("branches", []):
        addr = int(b["site"])
        if site - span <= addr < site:
            out.append({
                **b,
                "distance_to_call": site - addr,
            })
    out.sort(key=lambda x: x["site"])
    return out


def _nearby_strings(row: dict, site: int, span: int = 0x180) -> list[dict]:
    out = []
    for r in row.get("referenced_strings", []):
        materialize = int(r.get("materialize_address", r.get("lui_address", 0)))
        if abs(materialize - site) <= span:
            out.append(r)
    out.sort(key=lambda x: x.get("materialize_address", 0))
    return out


def _caller_sites_for(symbol_name: str, symbol_addr: int, all_calls: list[dict], funcs: list) -> list[dict]:
    rows = []
    for c in all_calls:
        if c.get("target") != symbol_addr:
            continue
        rows.append({
            **c,
            "caller": _owner_function(c["site"], funcs),
        })
    return rows


def build_predicate_report(main: str | Path, root_name: str = DEFAULT_ROOT) -> dict:
    path = Path(main)
    if not path.is_file():
        raise FileNotFoundError(path)

    symbols = _iter_symbols(path)
    by_name = _symbol_ranges(symbols)
    funcs = sorted(by_name.values(), key=lambda x: x.address)
    by_addr = {s.address: s.name for s in funcs}
    sections = _load_alloc_sections(path)
    all_calls = _all_direct_call_sites(path)

    root_sym = by_name.get(root_name)
    if not root_sym:
        raise RuntimeError(f"Root function not found: {root_name}")

    root = analyze_function(
        path, root_sym,
        symbols_by_addr=by_addr,
        alloc_sections=sections,
    )

    sinks = {}
    gate_slices = []
    for sink_name in DEFAULT_SINKS:
        sink_sym = by_name.get(sink_name)
        if sink_sym:
            sinks[sink_name] = {
                "address": sink_sym.address,
                "size": sink_sym.size,
                "caller_sites": _caller_sites_for(
                    sink_name, sink_sym.address, all_calls, funcs
                ),
            }

        for call in _call_sites(root, sink_name):
            site = int(call["site"])
            gate_slices.append({
                "source": root_name,
                "sink": sink_name,
                "call_site": site,
                "call_site_hex": _hex(site),
                "call_context": _instruction_window(root["disassembly"], site),
                "preceding_branches": _preceding_branches(root, site),
                "nearby_strings": _nearby_strings(root, site),
            })

    context_functions = {}
    for name in CONTEXT_TARGETS:
        sym = by_name.get(name)
        if not sym:
            continue
        row = analyze_function(
            path, sym,
            symbols_by_addr=by_addr,
            alloc_sections=sections,
        )
        context_functions[name] = {
            "address": sym.address,
            "address_hex": _hex(sym.address),
            "size": sym.size,
            "direct_calls": row["direct_calls"],
            "branches": row["branches"],
            "referenced_strings": row["referenced_strings"],
            "caller_sites": _caller_sites_for(name, sym.address, all_calls, funcs),
            "disassembly": row["disassembly"],
        }

    root_callers = _caller_sites_for(root_name, root_sym.address, all_calls, funcs)

    direct_onboarding = any(
        x["sink"] == "wlan_manager_onboarding_start"
        for x in gate_slices
    )

    return {
        "version": "1.0.17",
        "objective": (
            "Recover the exact branch predicate(s) inside the physical Wi-Fi "
            "link-status handler that gate entry into onboarding/re-onboarding. "
            "No RF injection is performed."
        ),
        "root": {
            "name": root_name,
            "address": root_sym.address,
            "address_hex": _hex(root_sym.address),
            "size": root_sym.size,
            "caller_sites": root_callers,
            "direct_calls": root["direct_calls"],
            "branches": root["branches"],
            "referenced_strings": root["referenced_strings"],
            "disassembly": root["disassembly"],
        },
        "sinks": sinks,
        "gate_slices": gate_slices,
        "context_functions": context_functions,
        "interpretation": {
            "direct_link_handler_to_onboarding_start": direct_onboarding,
            "what_is_confirmed_if_true": (
                "The firmware contains a direct static edge from the physical "
                "link-status handler to wlan_manager_onboarding_start."
                if direct_onboarding else
                "No direct static edge to wlan_manager_onboarding_start was recovered."
            ),
            "what_is_not_yet_proven": [
                "That an unauthenticated nearby 802.11 transmitter can select the gating branch.",
                "That taking the branch produces Tapo_Cam_* while the camera is normally bound.",
                "That re-onboarding is equivalent to factory reset or configuration erasure.",
            ],
            "next": (
                "Read gate_slices for the call to wlan_manager_onboarding_start. "
                "Identify the branch operands/status constants immediately preceding "
                "that call, then design only the RF experiment matching that predicate."
            ),
        },
    }


def _fmt_branch(b: dict) -> str:
    tgt = b.get("target")
    tgt_s = f"0x{tgt:08x}" if isinstance(tgt, int) else "?"
    return f"0x{b['site']:08x}: {b['mnemonic']} {b['operands']} -> {tgt_s}"


def markdown_report(report: dict) -> str:
    r = report["root"]
    lines = [
        "# S1 link-status → onboarding predicate slice — v1.0.17",
        "",
        "## Objective",
        "",
        report["objective"],
        "",
        "## Root function",
        "",
        f"- `{r['name']}` @ `{r['address_hex']}`, size `{r['size']}`",
        f"- recovered direct caller sites: `{len(r['caller_sites'])}`",
        "",
        "## Static bridge status",
        "",
        f"- direct link-handler → onboarding-start edge: "
        f"`{report['interpretation']['direct_link_handler_to_onboarding_start']}`",
        "",
    ]

    for g in report["gate_slices"]:
        lines += [
            f"## Gate slice: `{g['source']}` → `{g['sink']}`",
            "",
            f"Call site: `{g['call_site_hex']}`",
            "",
            "### Preceding branches",
            "",
        ]
        if g["preceding_branches"]:
            lines += [f"- `{_fmt_branch(x)}`" for x in g["preceding_branches"]]
        else:
            lines += ["- none recovered in the bounded pre-call window"]
        lines += ["", "### Nearby strings", ""]
        if g["nearby_strings"]:
            for s in g["nearby_strings"]:
                lines.append(
                    f"- `0x{s['address']:08x}`: `{s['string'].replace(chr(10), ' ')[:180]}`"
                )
        else:
            lines.append("- none recovered")
        lines += ["", "### Instruction slice", "", "```asm"]
        lines += g["call_context"]
        lines += ["```", ""]

    lines += [
        "## Interpretation discipline",
        "",
        "CONFIRMÉ: a direct call edge is static control-flow evidence.",
        "",
        "À TESTER: the exact runtime values/reason codes needed to choose that branch.",
        "",
        "NON DÉMONTRÉ: RF-only factory reset. Re-onboarding/SoftAP and factory reset "
        "remain separate states until configuration erasure/unbinding is observed.",
        "",
    ]
    return "\n".join(lines)


def write_predicate_report(report: dict, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / "s1-link-predicate.json"
    md_path = out / "s1-link-predicate.md"
    root_disasm = out / f"{report['root']['name']}.disasm.txt"

    write_json(json_path, report)
    md_path.write_text(markdown_report(report), encoding="utf-8", newline="\n")
    root_disasm.write_text(report["root"]["disassembly"], encoding="utf-8", newline="\n")

    ctx_dir = out / "context-functions"
    ctx_dir.mkdir(exist_ok=True)
    for name, row in report["context_functions"].items():
        (ctx_dir / f"{name}.disasm.txt").write_text(
            row["disassembly"], encoding="utf-8", newline="\n"
        )

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "root_disassembly": str(root_disasm),
        "context_dir": str(ctx_dir),
    }
