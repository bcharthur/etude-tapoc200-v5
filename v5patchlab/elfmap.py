from __future__ import annotations

from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

try:
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
except ImportError:
    Cs = None


def _deps():
    if ELFFile is None:
        raise RuntimeError(
            "pyelftools missing: pip install -r requirements-v5patchlab.txt"
        )
    if Cs is None:
        raise RuntimeError(
            "capstone missing: pip install -r requirements-v5patchlab.txt"
        )


def elf_info(path: str | Path) -> dict:
    _deps()
    with Path(path).open("rb") as f:
        elf = ELFFile(f)
        return {
            "machine": elf["e_machine"],
            "elfclass": elf.elfclass,
            "little_endian": elf.little_endian,
            "entry": int(elf["e_entry"]),
            "type": elf["e_type"],
        }


def _alloc_sections(elf):
    rows = []
    for sec in elf.iter_sections():
        flags = int(sec["sh_flags"])
        if not (flags & 0x2):  # SHF_ALLOC
            continue
        try:
            data = sec.data()
        except Exception:
            continue
        rows.append({
            "name": sec.name,
            "addr": int(sec["sh_addr"]),
            "offset": int(sec["sh_offset"]),
            "size": int(sec["sh_size"]),
            "data": data,
            "exec": bool(flags & 0x4),
        })
    return rows


def _symbols(elf):
    names = {}
    for secname in (".dynsym", ".symtab"):
        sec = elf.get_section_by_name(secname)
        if not sec:
            continue
        for sym in sec.iter_symbols():
            name = sym.name
            addr = int(sym["st_value"])
            if name and addr:
                names[addr] = name
    return names


def _find_string_vaddrs(sections, seed: str):
    needle = seed.encode()
    out = []
    for sec in sections:
        start = 0
        data = sec["data"]
        while True:
            pos = data.lower().find(needle.lower(), start)
            if pos < 0:
                break
            out.append({
                "section": sec["name"],
                "vaddr": sec["addr"] + pos,
                "section_offset": pos,
            })
            start = pos + 1
            if len(out) >= 50:
                break
    return out


def _disassemble_exec(sections):
    md = Cs(
        CS_ARCH_MIPS,
        CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN,
    )
    md.detail = False

    instructions = []
    for sec in sections:
        if not sec["exec"]:
            continue
        for ins in md.disasm(sec["data"], sec["addr"]):
            instructions.append({
                "address": ins.address,
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
            })
    return instructions


def _reg(s: str):
    return s.strip().replace("$", "")


def approximate_xrefs(path: str | Path, seeds: list[str]) -> dict:
    """Approximate MIPS address-materialization xrefs.

    Tracks `lui reg, hi` followed shortly by `addiu/ori reg, reg, lo`.
    This is a Ghidra seed generator, not a complete data-flow analysis.
    """
    _deps()
    p = Path(path)

    with p.open("rb") as f:
        elf = ELFFile(f)
        info = {
            "machine": elf["e_machine"],
            "elfclass": elf.elfclass,
            "little_endian": elf.little_endian,
            "entry": int(elf["e_entry"]),
        }

        if not elf.little_endian or "MIPS" not in str(elf["e_machine"]).upper():
            raise RuntimeError(
                f"Expected MIPS little-endian ELF, got {info}"
            )

        sections = _alloc_sections(elf)
        symbols = _symbols(elf)

    insns = _disassemble_exec(sections)
    seed_rows = {}

    for seed in seeds:
        string_locations = _find_string_vaddrs(sections, seed)
        wanted = {r["vaddr"] for r in string_locations}
        refs = []

        # Examine short windows after each LUI.
        for idx, ins in enumerate(insns):
            if ins["mnemonic"] != "lui":
                continue
            parts = [x.strip() for x in ins["op_str"].split(",")]
            if len(parts) != 2:
                continue
            reg = _reg(parts[0])
            try:
                hi = int(parts[1], 0) & 0xFFFF
            except ValueError:
                continue

            for j in range(idx + 1, min(idx + 7, len(insns))):
                nxt = insns[j]
                if nxt["mnemonic"] not in ("addiu", "ori"):
                    continue
                ops = [x.strip() for x in nxt["op_str"].split(",")]
                if len(ops) != 3:
                    continue
                if _reg(ops[0]) != reg or _reg(ops[1]) != reg:
                    continue
                try:
                    lo = int(ops[2], 0) & 0xFFFF
                except ValueError:
                    continue

                if nxt["mnemonic"] == "addiu" and lo & 0x8000:
                    low_signed = lo - 0x10000
                    address = ((hi << 16) + low_signed) & 0xFFFFFFFF
                else:
                    address = ((hi << 16) | lo) & 0xFFFFFFFF

                if address not in wanted:
                    continue

                start = max(0, idx - 12)
                end = min(len(insns), j + 20)
                context = insns[start:end]

                calls = []
                for ci in context:
                    if ci["mnemonic"] in ("jal", "bal"):
                        try:
                            target = int(ci["op_str"].split(",")[0].strip(), 0)
                        except Exception:
                            target = None
                        calls.append({
                            **ci,
                            "symbol": symbols.get(target) if target else None,
                        })

                refs.append({
                    "string_vaddr": address,
                    "lui_address": ins["address"],
                    "materialize_address": nxt["address"],
                    "context": context,
                    "calls": calls,
                })

        seed_rows[seed] = {
            "string_locations": string_locations,
            "approx_xrefs": refs,
        }

    return {
        "path": str(p),
        "elf": info,
        "seeds": seed_rows,
    }
