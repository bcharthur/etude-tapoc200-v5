from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .evidence import sha256_file
from .strings import extract_strings

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover
    ELFFile = None


SEED_GROUPS = {
    "factory_reset_state": [
        "factory reset", "factory_reset", "factory-reset", "factory default",
        "factory_default", "restore default", "restore_default", "reset device",
        "reset_device", "unbind", "unbound", "erase config", "clear config",
        "clear_config", "recovery", "recover", "reboot", "watchdog",
    ],
    "provisioning_softap": [
        "softap", "soft ap", "ap mode", "ap_mode", "provision", "onboarding",
        "quick setup", "quick_setup", "pairing", "default_userpw", "Tapo_Cam",
        "smartconfig", "wps", "dpp", "p2p", "wifi direct", "wifi_direct",
    ],
    "wifi_events": [
        "deauth", "disassoc", "disconnect", "link down", "link_down", "reconnect",
        "auth fail", "auth_fail", "assoc fail", "assoc_fail", "handshake",
        "reason code", "reason_code", "beacon", "probe request", "probe response",
        "channel switch", "csa", "roam", "scan result", "scan_result",
    ],
    "wifi_stack": [
        "wpa_supplicant", "hostapd", "nl80211", "cfg80211", "mac80211",
        "rtl8188", "wq9001", "esp32", "wlan_operate", "wireless", "802.11",
    ],
    "physical_reset_inputs": [
        "reset button", "reset_button", "long press", "long_press", "gpio",
        "button event", "button_event", "key event", "key_event",
    ],
    "network_only_not_s1_trigger": [
        "pake_register", "pake_share", "device_confirm", "securePassthrough",
        "third_account", "changeThirdAccount", "onvif", "rtsp", "/stream",
    ],
}

HIGH_SIGNAL_XREF_SEEDS = [
    "factory_reset", "factory reset", "restore_default", "softap", "Tapo_Cam",
    "deauth", "disassoc", "disconnect", "reconnect", "wpa_supplicant",
    "hostapd", "nl80211", "reset button", "long_press", "gpio", "recovery",
]


def _elf_file_offset_to_vaddr(path: Path, file_offset: int) -> tuple[str | None, int | None]:
    if ELFFile is None:
        return None, None
    with path.open("rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            off = int(sec["sh_offset"])
            size = int(sec["sh_size"])
            if size <= 0:
                continue
            if off <= file_offset < off + size:
                return sec.name, int(sec["sh_addr"]) + (file_offset - off)
    return None, None


def _symbol_hits(path: Path) -> list[dict]:
    if ELFFile is None:
        return []
    patterns = []
    for group, seeds in SEED_GROUPS.items():
        for seed in seeds:
            clean = re.sub(r"[^a-z0-9]+", ".*", seed.lower()).strip(".*")
            if clean:
                patterns.append((group, re.compile(clean, re.I)))

    out = []
    seen = set()
    with path.open("rb") as f:
        elf = ELFFile(f)
        for secname in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                name = sym.name or ""
                if not name:
                    continue
                matched = sorted({group for group, pat in patterns if pat.search(name)})
                if not matched:
                    continue
                key = (name, int(sym["st_value"]))
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "name": name,
                    "address": int(sym["st_value"]),
                    "size": int(sym["st_size"]),
                    "groups": matched,
                })
    out.sort(key=lambda x: (x["groups"], x["name"], x["address"]))
    return out


def scan_binary(path: str | Path) -> dict:
    p = Path(path)
    data = p.read_bytes()
    strings = extract_strings(data)
    groups = {}

    for group, seeds in SEED_GROUPS.items():
        rows = []
        seen = set()
        for off, text in strings:
            low = text.lower()
            matched = [seed for seed in seeds if seed.lower() in low]
            if not matched:
                continue
            key = (off, text)
            if key in seen:
                continue
            seen.add(key)
            sec, vaddr = _elf_file_offset_to_vaddr(p, off)
            rows.append({
                "offset": off,
                "vaddr": vaddr,
                "section": sec,
                "matched_seeds": matched,
                "string": text[:1000],
            })
            if len(rows) >= 250:
                break
        groups[group] = rows

    return {
        "path": str(p),
        "size": len(data),
        "sha256": sha256_file(p),
        "groups": groups,
        "symbols": _symbol_hits(p),
    }


def scan_rootfs(root: str | Path, max_file_size: int = 8 * 1024 * 1024) -> dict:
    root = Path(root)
    hits = []
    skipped = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        keep = []
        for name in dirnames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    continue
            except OSError:
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    continue
                st = p.stat()
                if st.st_size > max_file_size:
                    continue
                data = p.read_bytes()
            except OSError as exc:
                skipped.append({"path": str(p), "error": f"{type(exc).__name__}: {exc}"})
                continue

            text_hits = []
            for off, text in extract_strings(data):
                low = text.lower()
                matched_groups = {}
                for group, seeds in SEED_GROUPS.items():
                    matched = [seed for seed in seeds if seed.lower() in low]
                    if matched:
                        matched_groups[group] = matched
                if matched_groups:
                    text_hits.append({
                        "offset": off,
                        "groups": matched_groups,
                        "string": text[:700],
                    })
                    if len(text_hits) >= 100:
                        break
            if text_hits:
                hits.append({
                    "path": str(p),
                    "size": st.st_size,
                    "hits": text_hits,
                })
    return {
        "root": str(root),
        "files_with_hits": hits,
        "file_hit_count": len(hits),
        "skipped": skipped[:200],
        "skipped_count": len(skipped),
    }


def build_report(main: str | Path, rootfs: str | Path | None = None, *, xrefs: bool = False) -> dict:
    main = Path(main)
    result = {
        "scope": {
            "scenario": "S1 black-box RF",
            "success_condition": (
                "NORMAL/bound camera -> factory/provisioning state using only nearby radio frames; "
                "attacker is not associated, has no PSK, no IP reachability and no physical access."
            ),
            "important_boundary": (
                "TPAP/RTSP/ONVIF/HTTPS findings are chain-completion surfaces after a state pivot; "
                "they are not by themselves an S1 trigger while the camera remains a normal Wi-Fi STA."
            ),
        },
        "main": scan_binary(main),
        "rootfs": scan_rootfs(rootfs) if rootfs else None,
        "xrefs": None,
        "priorities": [
            {
                "priority": "P0",
                "question": "Can unauthenticated 802.11 management/action traffic force NORMAL -> SoftAP/provisioning/factory state?",
                "evidence_needed": "repeatable state transition with no association/PSK/IP/physical action",
            },
            {
                "priority": "P0",
                "question": "Does repeated radio-induced link failure trigger an unsafe recovery/fallback policy?",
                "evidence_needed": "bounded disconnect/roam failure sequence followed by Tapo_Cam_* or config erasure",
            },
            {
                "priority": "P1",
                "question": "Is there a pre-association parser surface in driver/firmware/P2P/WPS/DPP handling?",
                "evidence_needed": "specific management/action frame class reaches a parser before association",
            },
            {
                "priority": "CHAIN",
                "question": "If provisioning is reached, can existing TPAP0 + Streamd findings complete the attack chain?",
                "evidence_needed": "already demonstrated in SETUP; trigger remains the missing link",
            },
        ],
    }

    if xrefs:
        from .elfmap import approximate_xrefs
        result["xrefs"] = approximate_xrefs(main, HIGH_SIGNAL_XREF_SEEDS)

    return result


def markdown_summary(report: dict) -> str:
    lines = []
    lines.append("# S1 static map — black-box RF factory/provisioning pivot")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(report["scope"]["success_condition"])
    lines.append("")
    lines.append(f"Main: `{report['main']['path']}`")
    lines.append(f"SHA-256: `{report['main']['sha256']}`")
    lines.append("")
    lines.append("## Why this matters")
    lines.append("")
    lines.append(report["scope"]["important_boundary"])
    lines.append("")
    lines.append("## Binary hits")
    lines.append("")
    for group, rows in report["main"]["groups"].items():
        lines.append(f"### {group} ({len(rows)})")
        for row in rows[:40]:
            va = f"0x{row['vaddr']:08x}" if row.get("vaddr") is not None else "n/a"
            lines.append(f"- `off=0x{row['offset']:x}` `vaddr={va}` — `{row['string'][:180]}`")
        lines.append("")
    lines.append("## Matching ELF symbols")
    lines.append("")
    for row in report["main"]["symbols"][:150]:
        lines.append(
            f"- `0x{row['address']:08x}` `{row['name']}` size={row['size']} groups={','.join(row['groups'])}"
        )
    lines.append("")
    lines.append("## Priorities")
    lines.append("")
    for p in report["priorities"]:
        lines.append(f"- **{p['priority']}** — {p['question']}  ")
        lines.append(f"  Evidence: {p['evidence_needed']}")
    lines.append("")
    lines.append("## Interpretation rule")
    lines.append("")
    lines.append(
        "A crash/reboot is not a factory reset. A valid S1 result requires an observable and repeatable "
        "transition into provisioning/factory state (for example the camera advertising `Tapo_Cam_*`, "
        "losing prior binding/configuration, or equivalent state evidence) without association or physical action."
    )
    lines.append("")
    return "\n".join(lines)


def write_report(report: dict, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jp = out / "s1-static-map.json"
    mp = out / "s1-static-map.md"
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    mp.write_text(markdown_summary(report), encoding="utf-8")
    return {"json": str(jp), "markdown": str(mp)}
