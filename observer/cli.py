from __future__ import annotations

import argparse
import json
from pathlib import Path

from .preflight import preflight
from .report import build_report
from .session import mark_active, observe


def _print(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _ports(value: str) -> list[int]:
    out = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        p = int(item)
        if p < 1 or p > 65535:
            raise argparse.ArgumentTypeError(f"invalid port: {p}")
        out.append(p)
    if not out:
        raise argparse.ArgumentTypeError("at least one port is required")
    return sorted(set(out))


def cmd_preflight(args):
    _print(preflight(args.ip, args.env_file))
    return 0


def cmd_mark(args):
    _print(mark_active(args.text, args.kind))
    return 0


def cmd_analyze(args):
    run = Path(args.run)
    if not run.exists():
        raise FileNotFoundError(run)
    _print(build_report(run))
    return 0


def cmd_observe(args):
    capture_filter = args.pcap_filter
    run, report = observe(
        label=args.label,
        seconds=args.seconds,
        ip=args.ip,
        interval=args.interval,
        wifi_interval=args.wifi_interval,
        state_interval=args.state_interval,
        tapo_interval=args.tapo_interval,
        rtsp_heartbeat=args.rtsp_heartbeat,
        ports=args.ports,
        env_file=args.env_file,
        enable_wifi=not args.no_wifi,
        enable_rtsp=not args.no_rtsp,
        enable_tapo=not args.no_tapo,
        pcap_interface=args.pcap_interface,
        pcap_filter=capture_filter,
        capture_backend=args.capture_backend,
    )
    _print({"run": str(run), "summary": report})
    return 0


def cmd_passive(args):
    # Conservative, non-disruptive long observation profile. It generates
    # read-only probes and does not alter camera/AP state.
    run, report = observe(
        label=args.label,
        seconds=args.seconds,
        ip=args.ip,
        interval=0.5,
        wifi_interval=1.0,
        state_interval=3.0,
        tapo_interval=2.0,
        rtsp_heartbeat=3.0,
        ports=_ports("443,554,8800"),
        env_file=args.env_file,
        enable_wifi=True,
        enable_rtsp=not args.no_rtsp,
        enable_tapo=not args.no_tapo,
        pcap_interface=args.pcap_interface,
        pcap_filter=args.pcap_filter,
        capture_backend=args.capture_backend,
    )
    _print({"run": str(run), "summary": report})
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="Tapo C200 V5 synchronized network/state observer")
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("preflight", help="check optional dependencies and packet-capture interfaces")
    q.add_argument("--ip", default=None)
    q.add_argument("--env-file", default=".env.observer")
    q.set_defaults(func=cmd_preflight)

    q = sub.add_parser("observe", help="run a synchronized passive observation session")
    q.add_argument("--label", required=True)
    q.add_argument("--seconds", type=float, default=180.0, help="0 means until Ctrl+C")
    q.add_argument("--ip", default=None)
    q.add_argument("--interval", type=float, default=0.5, help="TCP probe interval")
    q.add_argument("--wifi-interval", type=float, default=2.0)
    q.add_argument("--state-interval", type=float, default=10.0)
    q.add_argument("--tapo-interval", type=float, default=5.0)
    q.add_argument("--rtsp-heartbeat", type=float, default=5.0)
    q.add_argument("--ports", type=_ports, default=_ports("443,554,8800"))
    q.add_argument("--env-file", default=".env.observer")
    q.add_argument("--no-wifi", action="store_true")
    q.add_argument("--no-rtsp", action="store_true")
    q.add_argument("--no-tapo", action="store_true")
    q.add_argument("--pcap-interface", default=None, help="dumpcap/tshark interface number or name from preflight")
    q.add_argument("--pcap-filter", default=None, help="BPF capture filter for Wireshark backend")
    q.add_argument("--capture-backend", choices=["auto", "wireshark", "pktmon", "none"], default="auto")
    q.set_defaults(func=cmd_observe)

    q = sub.add_parser("passive", help="non-disruptive deep observation profile; no AP/camera state changes")
    q.add_argument("--label", required=True)
    q.add_argument("--seconds", type=float, default=900.0)
    q.add_argument("--ip", default=None)
    q.add_argument("--env-file", default=".env.observer")
    q.add_argument("--no-rtsp", action="store_true")
    q.add_argument("--no-tapo", action="store_true")
    q.add_argument("--pcap-interface", default=None)
    q.add_argument("--pcap-filter", default=None)
    q.add_argument("--capture-backend", choices=["auto", "wireshark", "pktmon", "none"], default="auto")
    q.set_defaults(func=cmd_passive)

    q = sub.add_parser("mark", help="add an operator marker to the active session")
    q.add_argument("text")
    q.add_argument("--kind", default="MARK")
    q.set_defaults(func=cmd_mark)

    q = sub.add_parser("analyze", help="rebuild summary/merged timeline for a completed run")
    q.add_argument("run")
    q.set_defaults(func=cmd_analyze)
    return p


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[observerlab] ERROR: {type(exc).__name__}: {exc}")
        return 2
