from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover
    ELFFile = None

from .evidence import sha256_file
from .wsl import has_wsl, run_wsl, wsl_path


DEFAULT_TARGETS = [
    "onboarding_phy_link_status_change_handle",
    "wlan_manager_onboarding_start",
    "onboarding_restart",
    "wlan_manager_init_reconnect_ctx",
    "wlan_manual_reconnect",
    "wlan_manager_sta_disconnect",
    "wlan_sta_disconnect",
    "disconnect_WiFi_ex",
    "is_reonboarding",
    "get_cur_onboarding_mode",
    "set_exit_softap_fast_flag",
    "stop_exit_softap",
    "set_onboarding_finished",
    "onboarding_set_start_flag",
    "is_onboarding_finished",
    "is_onboarding_started",
    "ffs_onboarding_start",
    "ffs_onboarding_stop",
    "wlan_manager_reboot",
    "wlan_manager_reboot_thread",
]

BRANCH_PREFIXES = (
    "b", "beq", "bne", "beqz", "bnez", "bgez", "bgtz", "blez", "bltz",
)
DIRECT_CALLS = {"jal", "jalx", "bal"}
INDIRECT_CALLS = {"jalr"}

STATE_TERMS = {
    "link": ("disconnect", "reconnect", "link", "wlan", "sta_"),
    "onboarding": ("onboarding", "reonboarding", "provision"),
    "softap": ("softap", "tapo_cam", "ap mode", "ap_mode"),
    "reboot": ("reboot", "watchdog"),
    "recovery": ("recovery", "recover"),
    "factory": ("factory", "unbind", "clear config", "erase config"),
}


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    bind: str
    sym_type: str
    section: str


@dataclass(frozen=True)
class Insn:
    address: int
    mnemonic: str
    operands: str
    symbol: str | None
    raw: str


def _need_pyelftools() -> None:
    if ELFFile is None:
        raise RuntimeError("pyelftools missing: pip install -r requirements-v5patchlab.txt")


def _iter_symbols(path: Path) -> list[Symbol]:
    _need_pyelftools()
    rows: dict[tuple[str, int], Symbol] = {}
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                name = sym.name or ""
                address = int(sym["st_value"])
                if not name or not address:
                    continue
                row = Symbol(
                    name=name,
                    address=address,
                    size=int(sym["st_size"]),
                    bind=str(sym["st_info"]["bind"]),
                    sym_type=str(sym["st_info"]["type"]),
                    section=str(sym["st_shndx"]),
                )
                key = (name, address)
                # Prefer rows with a real size.
                if key not in rows or row.size > rows[key].size:
                    rows[key] = row
    return sorted(rows.values(), key=lambda x: (x.address, x.name))


def _symbol_ranges(symbols: list[Symbol]) -> dict[str, Symbol]:
    funcs = [s for s in symbols if "FUNC" in s.sym_type.upper()]
    by_name: dict[str, Symbol] = {}
    for idx, sym in enumerate(funcs):
        size = sym.size
        if size <= 0:
            for nxt in funcs[idx + 1:]:
                if nxt.address > sym.address:
                    size = nxt.address - sym.address
                    break
        if size <= 0:
            size = 4
        row = Symbol(sym.name, sym.address, size, sym.bind, sym.sym_type, sym.section)
        old = by_name.get(sym.name)
        if old is None or row.size > old.size:
            by_name[sym.name] = row
    return by_name


def _choose_objdump() -> tuple[str, str]:
    """Return (mode, command). mode is native or wsl."""
    for name in ("mipsel-linux-gnu-objdump", "mips-linux-gnu-objdump"):
        p = shutil.which(name)
        if p:
            return "native", p
    if has_wsl():
        for name in ("mipsel-linux-gnu-objdump", "mips-linux-gnu-objdump"):
            cp = run_wsl(f"command -v {name}", check=False)
            if cp.returncode == 0 and cp.stdout.strip():
                return "wsl", name
    raise RuntimeError(
        "MIPS objdump not found. Install binutils-mipsel-linux-gnu in Ubuntu WSL: "
        "sudo apt update && sudo apt install -y binutils-mipsel-linux-gnu"
    )


def _run_objdump(path: Path, *, start: int | None = None, stop: int | None = None) -> str:
    mode, tool = _choose_objdump()
    args = [tool, "-d"]
    if start is not None:
        args += [f"--start-address=0x{start:x}"]
    if stop is not None:
        args += [f"--stop-address=0x{stop:x}"]

    if mode == "native":
        cp = subprocess.run(
            args + [str(path)], capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if cp.returncode != 0:
            raise RuntimeError(f"objdump failed: {cp.stderr}")
        return cp.stdout

    wp = wsl_path(path)
    quoted = wp.replace("'", "'\\''")
    cmd = " ".join(args) + f" '{quoted}'"
    cp = run_wsl(cmd, check=False)
    if cp.returncode != 0:
        raise RuntimeError(f"WSL objdump failed:\n{cp.stderr}\n{cp.stdout}")
    return cp.stdout


_INSN_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}\s+)?([a-zA-Z0-9_.]+)\s*(.*?)\s*$"
)
_SYMBOL_SUFFIX_RE = re.compile(r"<([^>]+)>\s*$")
_HEX_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(?:0x)?([0-9a-fA-F]{5,8})(?![A-Za-z0-9_])")


def parse_objdump(text: str) -> list[Insn]:
    out: list[Insn] = []
    for line in text.splitlines():
        m = _INSN_RE.match(line)
        if not m:
            continue
        symbol = None
        sm = _SYMBOL_SUFFIX_RE.search(m.group(3))
        if sm:
            symbol = sm.group(1)
        out.append(Insn(
            address=int(m.group(1), 16),
            mnemonic=m.group(2).lower(),
            operands=m.group(3).strip(),
            symbol=symbol,
            raw=line.rstrip(),
        ))
    return out


def _first_target(operands: str) -> int | None:
    # Prefer explicit 0x-prefixed operands; then bare hex addresses as emitted by objdump.
    for tok in re.split(r"[\s,()]+", operands):
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith("0x"):
            try:
                return int(tok, 16)
            except ValueError:
                pass
        if re.fullmatch(r"[0-9a-fA-F]{6,8}", tok):
            try:
                return int(tok, 16)
            except ValueError:
                pass
    return None


def _parse_imm(token: str) -> int | None:
    token = token.strip()
    try:
        return int(token, 0)
    except ValueError:
        if re.fullmatch(r"[0-9a-fA-F]+", token):
            try:
                return int(token, 16)
            except ValueError:
                return None
        return None


def _reg(token: str) -> str:
    return token.strip().replace("$", "")


def _materialized_addresses(insns: list[Insn]) -> list[dict]:
    rows = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "lui":
            continue
        ops = [x.strip() for x in ins.operands.split(",")]
        if len(ops) < 2:
            continue
        reg = _reg(ops[0])
        hi = _parse_imm(ops[1])
        if hi is None:
            continue
        hi &= 0xFFFF
        for nxt in insns[i + 1:i + 9]:
            if nxt.mnemonic not in ("addiu", "ori"):
                continue
            nops = [x.strip() for x in nxt.operands.split(",")]
            if len(nops) < 3 or _reg(nops[0]) != reg or _reg(nops[1]) != reg:
                continue
            lo = _parse_imm(nops[2])
            if lo is None:
                continue
            lo &= 0xFFFF
            if nxt.mnemonic == "addiu" and (lo & 0x8000):
                addr = ((hi << 16) + (lo - 0x10000)) & 0xFFFFFFFF
            else:
                addr = ((hi << 16) | lo) & 0xFFFFFFFF
            rows.append({
                "address": addr,
                "lui_address": ins.address,
                "materialize_address": nxt.address,
                "register": reg,
            })
            break
    return rows


def _load_alloc_sections(path: Path) -> list[dict]:
    _need_pyelftools()
    out = []
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            flags = int(sec["sh_flags"])
            if not (flags & 0x2):  # SHF_ALLOC
                continue
            try:
                data = sec.data()
            except Exception:
                continue
            out.append({
                "name": sec.name,
                "addr": int(sec["sh_addr"]),
                "size": int(sec["sh_size"]),
                "data": data,
            })
    return out


def _string_at(sections: list[dict], address: int, max_len: int = 240) -> tuple[str | None, str | None]:
    for sec in sections:
        start = sec["addr"]
        end = start + sec["size"]
        if not (start <= address < end):
            continue
        pos = address - start
        data: bytes = sec["data"]
        if pos >= len(data):
            return sec["name"], None
        chunk = data[pos:pos + max_len]
        zero = chunk.find(b"\x00")
        if zero >= 0:
            chunk = chunk[:zero]
        if len(chunk) < 3:
            return sec["name"], None
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk)
        if not chunk or printable / len(chunk) < 0.88:
            return sec["name"], None
        return sec["name"], chunk.decode("utf-8", errors="replace")
    return None, None


def _classify_text(text: str) -> list[str]:
    low = text.lower()
    return sorted(name for name, terms in STATE_TERMS.items() if any(t in low for t in terms))


def _context(insns: list[Insn], idx: int, before: int = 8, after: int = 6) -> list[str]:
    return [x.raw for x in insns[max(0, idx - before): min(len(insns), idx + after + 1)]]


def analyze_function(
    path: Path,
    sym: Symbol,
    *,
    symbols_by_addr: dict[int, str],
    alloc_sections: list[dict],
) -> dict:
    text = _run_objdump(path, start=sym.address, stop=sym.address + max(sym.size, 4))
    insns = parse_objdump(text)
    calls = []
    indirect_calls = []
    branches = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic in DIRECT_CALLS:
            target = _first_target(ins.operands)
            calls.append({
                "site": ins.address,
                "mnemonic": ins.mnemonic,
                "target": target,
                "target_symbol": symbols_by_addr.get(target) if target is not None else ins.symbol,
                "objdump_symbol": ins.symbol,
                "context": _context(insns, idx),
            })
        elif ins.mnemonic in INDIRECT_CALLS:
            indirect_calls.append({
                "site": ins.address,
                "mnemonic": ins.mnemonic,
                "operands": ins.operands,
                "context": _context(insns, idx),
            })
        elif ins.mnemonic.startswith(BRANCH_PREFIXES):
            target = _first_target(ins.operands)
            branches.append({
                "site": ins.address,
                "mnemonic": ins.mnemonic,
                "operands": ins.operands,
                "target": target,
                "target_symbol": symbols_by_addr.get(target) if target is not None else ins.symbol,
            })

    refs = []
    seen = set()
    for row in _materialized_addresses(insns):
        sec, s = _string_at(alloc_sections, row["address"])
        if not s:
            continue
        key = (row["address"], s)
        if key in seen:
            continue
        seen.add(key)
        refs.append({
            **row,
            "section": sec,
            "string": s,
            "state_groups": _classify_text(s),
        })

    return {
        "name": sym.name,
        "address": sym.address,
        "size": sym.size,
        "end": sym.address + sym.size,
        "instruction_count": len(insns),
        "direct_calls": calls,
        "indirect_calls": indirect_calls,
        "branches": branches,
        "referenced_strings": refs,
        "name_state_groups": _classify_text(sym.name),
        "disassembly": text,
    }


def _all_direct_call_sites(path: Path) -> list[dict]:
    """Scan only call lines from the whole binary to recover direct callers."""
    mode, tool = _choose_objdump()
    if mode == "native":
        # Use objdump and parse; keeping the full text here is acceptable for this ~4 MB ELF.
        cp = subprocess.run(
            [tool, "-d", str(path)], capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr)
        lines = cp.stdout
    else:
        wp = wsl_path(path).replace("'", "'\\''")
        # Filter inside WSL so Windows does not receive the full disassembly.
        cmd = (
            f"{tool} -d '{wp}' | "
            "grep -E '^[[:space:]]*[0-9a-f]+:.*[[:space:]](jal|jalx|bal)[[:space:]]' || true"
        )
        cp = run_wsl(cmd, check=False)
        lines = cp.stdout

    rows = []
    for ins in parse_objdump(lines):
        if ins.mnemonic not in DIRECT_CALLS:
            continue
        rows.append({
            "site": ins.address,
            "mnemonic": ins.mnemonic,
            "target": _first_target(ins.operands),
            "objdump_symbol": ins.symbol,
            "raw": ins.raw,
        })
    return rows


def _owner_function(address: int, funcs: list[Symbol]) -> str | None:
    # funcs are sorted by address and contain inferred non-zero sizes.
    lo, hi = 0, len(funcs)
    while lo < hi:
        mid = (lo + hi) // 2
        if funcs[mid].address <= address:
            lo = mid + 1
        else:
            hi = mid
    idx = lo - 1
    if idx < 0:
        return None
    f = funcs[idx]
    if f.address <= address < f.address + max(f.size, 4):
        return f.name
    return None


def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:140]


def _bridge_candidates(functions: dict[str, dict], callers: dict[str, list[dict]]) -> list[dict]:
    out = []
    for name, row in functions.items():
        groups = set(row.get("name_state_groups", []))
        for r in row.get("referenced_strings", []):
            groups.update(r.get("state_groups", []))
        direct_target_names = {
            c.get("target_symbol") or c.get("objdump_symbol")
            for c in row.get("direct_calls", [])
        }
        direct_target_names.discard(None)
        callee_groups = set()
        for callee in direct_target_names:
            callee_groups.update(_classify_text(callee))
        combined = groups | callee_groups

        score = 0
        reasons = []
        if "link" in combined:
            score += 4; reasons.append("link/WLAN state")
        if "onboarding" in combined:
            score += 5; reasons.append("onboarding/re-onboarding")
        if "softap" in combined:
            score += 5; reasons.append("SoftAP")
        if "reboot" in combined:
            score += 2; reasons.append("reboot")
        if "factory" in combined:
            score += 3; reasons.append("factory/unbind marker")
        if "recovery" in combined:
            score += 1; reasons.append("recovery marker")
        if callers.get(name):
            score += min(3, len(callers[name]))
            reasons.append(f"{len(callers[name])} direct call site(s)")

        if score:
            out.append({
                "name": name,
                "score": score,
                "groups": sorted(combined),
                "reasons": reasons,
                "direct_callees": sorted(direct_target_names),
                "direct_callers": sorted({x.get("caller") for x in callers.get(name, []) if x.get("caller")}),
                "direct_caller_sites": [
                    {
                        "site": x.get("site"),
                        "caller": x.get("caller"),
                        "raw": x.get("raw"),
                    }
                    for x in callers.get(name, [])
                ],
            })
    return sorted(out, key=lambda x: (-x["score"], x["name"]))


def build_controlflow_report(
    main: str | Path,
    *,
    targets: Iterable[str] | None = None,
) -> dict:
    path = Path(main)
    if not path.is_file():
        raise FileNotFoundError(path)

    info = {}
    _need_pyelftools()
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        info = {
            "machine": str(elf["e_machine"]),
            "elfclass": elf.elfclass,
            "little_endian": bool(elf.little_endian),
            "entry": int(elf["e_entry"]),
        }
    if "MIPS" not in info["machine"].upper() or not info["little_endian"]:
        raise RuntimeError(f"Expected little-endian MIPS ELF, got {info}")

    symbols = _iter_symbols(path)
    by_name = _symbol_ranges(symbols)
    funcs = sorted(by_name.values(), key=lambda x: x.address)
    by_addr = {s.address: s.name for s in funcs}
    sections = _load_alloc_sections(path)

    requested = list(targets or DEFAULT_TARGETS)
    found: dict[str, dict] = {}
    missing = []
    for name in requested:
        sym = by_name.get(name)
        if not sym:
            missing.append(name)
            continue
        found[name] = analyze_function(
            path, sym, symbols_by_addr=by_addr, alloc_sections=sections,
        )

    all_calls = _all_direct_call_sites(path)
    callers: dict[str, list[dict]] = {name: [] for name in found}
    target_addrs = {row["address"]: name for name, row in found.items()}
    for call in all_calls:
        target = call.get("target")
        name = target_addrs.get(target)
        if not name:
            continue
        caller = _owner_function(call["site"], funcs)
        callers[name].append({**call, "caller": caller})

    bridges = _bridge_candidates(found, callers)

    edges = []
    for src_name, row in found.items():
        for call in row["direct_calls"]:
            dst = call.get("target_symbol") or call.get("objdump_symbol")
            if dst:
                edges.append({
                    "source": src_name,
                    "target": dst,
                    "site": call["site"],
                    "target_address": call.get("target"),
                    "target_in_requested_set": dst in found,
                })

    return {
        "version": "1.0.16",
        "main": {
            "path": str(path),
            "sha256": sha256_file(path),
            "elf": info,
        },
        "objective": (
            "Recover the exact static junction from Wi-Fi link-state events into "
            "re-onboarding/SoftAP/reboot state logic before designing an RF trigger."
        ),
        "requested_targets": requested,
        "missing_targets": missing,
        "functions": found,
        "callers": callers,
        "edges": edges,
        "bridge_candidates": bridges,
        "limitations": [
            "Direct bal/jal edges are resolved; PIC jalr/t9 calls remain explicitly unresolved.",
            "String references are heuristic LUI+ADDIU/ORI materializations and must be checked in Ghidra for final data-flow truth.",
            "Static evidence does not prove that unauthenticated 802.11 traffic can reach a factory/provisioning transition.",
            "Recovery and factory reset remain distinct states unless configuration erasure/unbinding is directly demonstrated.",
        ],
        "next_decision": {
            "P0": (
                "Inspect onboarding_phy_link_status_change_handle first: identify its callers, "
                "reason/status arguments, counters/timeouts and any path to wlan_manager_onboarding_start, "
                "onboarding_restart or SoftAP flags."
            ),
            "only_after_static_condition_is_known": (
                "Design one bounded RF experiment matching that specific condition and observe for Tapo_Cam_* / re-onboarding."
            ),
        },
    }


def markdown_report(report: dict) -> str:
    lines = [
        "# S1 onboarding control-flow — v1.0.16",
        "",
        "## Objective",
        "",
        report["objective"],
        "",
        f"Main: `{report['main']['path']}`",
        f"SHA-256: `{report['main']['sha256']}`",
        "",
        "## Priority bridge candidates",
        "",
    ]
    for row in report["bridge_candidates"][:20]:
        lines.append(
            f"- **{row['score']}** `{row['name']}` — groups: {', '.join(row['groups']) or 'none'}; "
            f"reasons: {', '.join(row['reasons'])}"
        )
    lines += ["", "## Target functions", ""]
    for name, row in report["functions"].items():
        lines.append(f"### `{name}` @ `0x{row['address']:08x}` size={row['size']}")
        if report["callers"].get(name):
            callers = sorted({c.get("caller") or f"0x{c['site']:08x}" for c in report["callers"][name]})
            lines.append(f"Direct callers: {', '.join(f'`{x}`' for x in callers)}")
        else:
            lines.append("Direct callers: none recovered (may be indirect/PIC).")
        direct = [c.get("target_symbol") or c.get("objdump_symbol") for c in row["direct_calls"]]
        direct = [x for x in direct if x]
        if direct:
            lines.append(f"Direct callees: {', '.join(f'`{x}`' for x in sorted(set(direct)))}")
        if row["referenced_strings"]:
            lines.append("Referenced strings:")
            for s in row["referenced_strings"][:30]:
                short = s["string"].replace("\n", "\\n")[:180]
                lines.append(
                    f"- `0x{s['address']:08x}` [{','.join(s['state_groups']) or '-'}] `{short}`"
                )
        lines.append("")

    lines += [
        "## Interpretation",
        "",
        "`CONFIRMÉ` means a static direct call/string/branch is present in this ELF.",
        "",
        "`HYPOTHÈSE` means the junction may convert RF/link failure into onboarding/SoftAP; static proximity alone is not enough.",
        "",
        "`À TESTER` begins only after the controlling branch/timeout/reason-code is identified.",
        "",
        "## Important limitation",
        "",
        "A reboot or `/tmp/recovery_mode` is not a factory reset. The S1 success condition remains a repeatable "
        "radio-only transition into re-onboarding/SoftAP/unbound/factory state with no PSK, association, IP path or physical action.",
        "",
    ]
    if report["missing_targets"]:
        lines += ["## Missing symbols", ""]
        for name in report["missing_targets"]:
            lines.append(f"- `{name}`")
        lines.append("")
    return "\n".join(lines)


def _dot(report: dict) -> str:
    lines = ["digraph s1_controlflow {", "  rankdir=LR;"]
    target_names = set(report["functions"])
    nodes = set(target_names)
    for e in report["edges"]:
        nodes.add(e["target"])
    for n in sorted(nodes):
        attrs = []
        if n in target_names:
            attrs.append('shape="box"')
        label = n.replace('"', "'")
        attrs.append(f'label="{label}"')
        lines.append(f'  "{label}" [{", ".join(attrs)}];')
    for e in report["edges"]:
        src = e["source"].replace('"', "'")
        dst = e["target"].replace('"', "'")
        lines.append(f'  "{src}" -> "{dst}" [label="0x{e["site"]:x}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_controlflow_report(report: dict, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / "s1-controlflow.json"
    md_path = out / "s1-controlflow.md"
    dot_path = out / "s1-controlflow.dot"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    md_path.write_text(markdown_report(report), encoding="utf-8")
    dot_path.write_text(_dot(report), encoding="utf-8")

    fn_dir = out / "functions"
    fn_dir.mkdir(exist_ok=True)
    for name, row in report["functions"].items():
        base = fn_dir / _safe_filename(name)
        (base.with_suffix(".disasm.txt")).write_text(row["disassembly"], encoding="utf-8")
        slim = {k: v for k, v in row.items() if k != "disassembly"}
        slim["direct_callers"] = report["callers"].get(name, [])
        (base.with_suffix(".json")).write_text(
            json.dumps(slim, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "dot": str(dot_path),
        "functions_dir": str(fn_dir),
    }
