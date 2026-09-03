from __future__ import annotations

import json
from pathlib import Path

from .evidence import write_json


DEFAULT_TERMS = [
    "factory_reset", "factory_default", "reset_wifi", "unbind",
    "provision", "softap", "reboot", "watchdog", "/dev/mtd",
    "/stream", "authorization", "pake_register", "default_userpw",
]


def _need_optional():
    try:
        from elftools.elf.elffile import ELFFile
        from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
        return ELFFile, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    except ImportError as exc:
        raise RuntimeError(
            "mips-map requires optional packages: "
            "pip install pyelftools capstone"
        ) from exc


def _strings_with_vaddr(elf, terms):
    out = []
    lowers = [x.lower() for x in terms]

    for section in elf.iter_sections():
        try:
            flags = section["sh_flags"]
            addr = section["sh_addr"]
            data = section.data()
        except Exception:
            continue

        if not addr or not data:
            continue

        start = None
        for i, b in enumerate(data):
            printable = 32 <= b <= 126
            if printable and start is None:
                start = i
            elif not printable and start is not None:
                if i - start >= 4:
                    s = data[start:i].decode("ascii", errors="replace")
                    low = s.lower()
                    matched = [t for t in terms if t.lower() in low]
                    if matched:
                        out.append({
                            "section": section.name,
                            "offset": start,
                            "vaddr": addr + start,
                            "string": s,
                            "matched": matched,
                        })
                start = None

    return out


def _reg_id(name, mips_const):
    # Capstone exposes register names through instruction operands; we keep
    # register values symbolically by numeric id instead of importing constants.
    return name


def mips_map(binary: str, out_dir: str, terms: list[str] | None = None):
    ELFFile, Cs, ARCH, MODE32, LE = _need_optional()
    terms = terms or DEFAULT_TERMS

    p = Path(binary)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    with p.open("rb") as f:
        elf = ELFFile(f)

        header = {
            "path": str(p),
            "elfclass": elf.elfclass,
            "little_endian": elf.little_endian,
            "machine": elf["e_machine"],
            "entry": elf["e_entry"],
        }

        hits = _strings_with_vaddr(elf, terms)
        by_addr = {x["vaddr"]: x for x in hits}

        text = elf.get_section_by_name(".text")
        if text is None:
            result = {
                "header": header,
                "string_hits": hits,
                "xrefs": [],
                "warning": "No .text section found.",
            }
            write_json(out / "mips-map.json", result)
            return result

        code = text.data()
        base = text["sh_addr"]

        md = Cs(ARCH, MODE32 | LE)
        md.detail = False

        # Approximate MIPS string xrefs:
        #   lui  $r, HI
        #   addiu/ori $r, $r, LO
        #
        # Track last LUI value by textual register. This intentionally favors
        # useful candidates over pretending to be a full data-flow engine.
        high = {}
        xrefs = []

        targets = sorted(hits, key=lambda x: x["vaddr"])

        def nearby_target(addr):
            for h in targets:
                if h["vaddr"] <= addr < h["vaddr"] + max(1, len(h["string"]) + 1):
                    return h
            return None

        history = []

        for ins in md.disasm(code, base):
            history.append({
                "address": ins.address,
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
            })
            if len(history) > 12:
                history.pop(0)

            ops = [x.strip() for x in ins.op_str.split(",")]

            if ins.mnemonic == "lui" and len(ops) == 2:
                try:
                    reg = ops[0]
                    imm = int(ops[1], 0) & 0xffff
                    high[reg] = imm << 16
                except Exception:
                    pass

            elif ins.mnemonic in {"addiu", "ori"} and len(ops) == 3:
                dst, src, imm_s = ops
                if src in high:
                    try:
                        imm = int(imm_s, 0) & 0xffff
                        if ins.mnemonic == "addiu" and imm & 0x8000:
                            imm -= 0x10000
                        addr = (high[src] + imm) & 0xffffffff
                        h = nearby_target(addr)
                        if h:
                            xrefs.append({
                                "code_address": ins.address,
                                "code_address_hex": hex(ins.address),
                                "computed_address": addr,
                                "string_vaddr": h["vaddr"],
                                "string": h["string"],
                                "matched": h["matched"],
                                "context": list(history),
                            })
                    except Exception:
                        pass

        symbols = []
        for sec_name in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(sec_name)
            if sec is None:
                continue
            for sym in sec.iter_symbols():
                name = sym.name
                if not name:
                    continue
                low = name.lower()
                if any(t in low for t in [
                    "strcpy","sprintf","memcpy","memmove","system","reboot",
                    "ioctl","open","write","watchdog","mtd","reset","flash"
                ]):
                    symbols.append({
                        "table": sec_name,
                        "name": name,
                        "value": sym["st_value"],
                        "value_hex": hex(sym["st_value"]),
                        "size": sym["st_size"],
                    })

        result = {
            "header": header,
            "terms": terms,
            "string_hits": hits,
            "approximate_string_xrefs": xrefs,
            "interesting_symbols": symbols,
            "notes": [
                "String xrefs are heuristic MIPS LUI+ADDIU/ORI candidates.",
                "Use the code addresses as Ghidra navigation seeds, not as proof of a call path."
            ],
        }

        write_json(out / "mips-map.json", result)
        return result
