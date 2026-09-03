from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .config import load_scope
from .identify import identify
from .scope import assert_mac_expected, ScopeError
from .probes import probe_ports
from .rtsp import rtsp_options, rtsp_baseline
from .onvif import onvif_get_device_information, onvif_matrix
from .raw_capture import (
    capture_windows_ipv4,
    list_ipv4_interfaces,
    route_local_ip,
)
from .pcap import summarize_pcap
from .pcap_conversations import tcp_conversations
from .wsdiscovery import ws_discovery_probe
from .tlsprobe import tls_fingerprint
from .probe8800 import passive_probe_8800
from .evidence import new_run_dir, write_json, build_manifest
from .pathutil import resolve_pcap
from .recon_capture import run_recon_with_capture

console = Console()


def show_ident(data):
    table = Table(title="Identification cible")
    table.add_column("Champ")
    table.add_column("Valeur")
    for key in (
        "device_name", "configured_ip", "expected_mac", "reachable",
        "observed_mac", "mac_match", "rediscovered_ip"
    ):
        table.add_row(key, str(data.get(key)))
    console.print(table)


def validated_scope():
    scope = load_scope()
    data = identify(scope)
    show_ident(data)
    assert_mac_expected(scope, data.get("observed_mac"))
    return scope, data


def cmd_identify(args):
    scope = load_scope()
    data = identify(scope, rediscover=args.rediscover)
    show_ident(data)
    return 0 if data["mac_match"] else 2


def cmd_discover(args):
    scope = load_scope()
    data = identify(scope, rediscover=True)
    show_ident(data)
    if data.get("rediscovered_ip"):
        console.print(f"[green]MAC trouvée à {data['rediscovered_ip']}[/green]")
        return 0
    return 2


def cmd_interfaces(args):
    scope = load_scope()
    routed = route_local_ip(scope.target_ip)
    table = Table(title="Interfaces IPv4")
    table.add_column("Interface")
    table.add_column("IPv4")
    table.add_column("Route vers caméra")
    for iface in list_ipv4_interfaces():
        table.add_row(
            iface.name,
            ", ".join(iface.ipv4),
            "oui" if routed in iface.ipv4 else "",
        )
    console.print(table)
    console.print(f"[cyan]IP locale choisie:[/cyan] {routed}")
    return 0


def cmd_ports(args):
    scope, _ = validated_scope()
    rows = probe_ports(scope.target_ip, scope.tcp_ports, args.timeout)
    table = Table(title=f"TCP baseline — {scope.target_ip}")
    table.add_column("Port")
    table.add_column("État")
    table.add_column("Temps")
    table.add_column("Erreur")
    for row in rows:
        table.add_row(
            str(row["port"]),
            "OPEN" if row["open"] else "closed/filtered",
            f"{row['elapsed_ms']} ms",
            str(row["error"] or ""),
        )
    console.print(table)
    return 0


def cmd_rtsp(args):
    scope, _ = validated_scope()
    console.print_json(data=rtsp_options(scope.target_ip, timeout=args.timeout))
    return 0


def cmd_rtsp_describe(args):
    scope, _ = validated_scope()
    console.print_json(data=rtsp_baseline(scope.target_ip, timeout=args.timeout))
    return 0


def cmd_onvif(args):
    scope, _ = validated_scope()
    console.print_json(
        data=onvif_get_device_information(scope.target_ip, timeout=args.timeout)
    )
    return 0


def cmd_onvif_matrix(args):
    scope, _ = validated_scope()
    console.print_json(data=onvif_matrix(scope.target_ip, timeout=args.timeout))
    return 0


def cmd_ws_discovery(args):
    scope, _ = validated_scope()
    local_ip = args.local_ip or route_local_ip(scope.target_ip)
    console.print_json(data=ws_discovery_probe(
        scope.target_ip, local_ip, timeout=args.timeout
    ))
    return 0


def cmd_tls(args):
    scope, _ = validated_scope()
    console.print_json(data=tls_fingerprint(
        scope.target_ip, port=args.port, timeout=args.timeout
    ))
    return 0


def cmd_probe8800(args):
    scope, _ = validated_scope()
    console.print_json(data=passive_probe_8800(
        scope.target_ip, wait_seconds=args.wait
    ))
    return 0


def cmd_capture(args):
    scope, _ = validated_scope()
    run = new_run_dir()
    local_ip = args.local_ip or route_local_ip(scope.target_ip)
    pcap = run / "capture.pcap"

    meta = capture_windows_ipv4(
        local_ip=local_ip,
        target_ip=scope.target_ip,
        output=pcap,
        seconds=args.seconds,
    )
    write_json(run / "capture.json", meta)

    if meta.get("ok") and pcap.exists():
        summary = summarize_pcap(pcap, scope.target_ip)
        write_json(run / "capture-summary.json", summary)
        console.print_json(data=summary)
    else:
        console.print_json(data=meta)

    write_json(
        run / "manifest.json",
        build_manifest(run, {
            "target_ip": scope.target_ip,
            "target_mac": scope.target_mac,
        }),
    )
    console.print(f"[cyan]Run:[/cyan] {run}")
    return 0 if meta.get("ok") else 3


def cmd_analyze(args):
    scope = load_scope()
    pcap = resolve_pcap(args.pcap)
    console.print(f"[cyan]PCAP:[/cyan] {pcap}")
    console.print_json(data=summarize_pcap(pcap, scope.target_ip))
    return 0


def cmd_conversations(args):
    scope = load_scope()
    pcap = resolve_pcap(args.pcap)
    console.print(f"[cyan]PCAP:[/cyan] {pcap}")
    console.print_json(data=tcp_conversations(pcap, scope.target_ip))
    return 0


def _run_recon(scope, args):
    local_ip = route_local_ip(scope.target_ip)
    return {
        "target": {
            "name": scope.device_name,
            "ip": scope.target_ip,
            "mac": scope.target_mac,
            "local_ip": local_ip,
        },
        "rtsp": rtsp_baseline(scope.target_ip, timeout=args.timeout),
        "ws_discovery": ws_discovery_probe(
            scope.target_ip, local_ip, timeout=args.ws_timeout
        ),
        "tls_443": tls_fingerprint(
            scope.target_ip, 443, timeout=args.timeout
        ),
        "tcp_8800_passive": passive_probe_8800(
            scope.target_ip, wait_seconds=args.passive_wait
        ),
        "onvif_matrix": onvif_matrix(
            scope.target_ip, timeout=args.timeout
        ),
    }


def cmd_recon_v2(args):
    scope, _ = validated_scope()
    run = new_run_dir()
    result = _run_recon(scope, args)
    write_json(run / "recon-v2.json", result)
    write_json(run / "manifest.json", build_manifest(
        run, {"tool": "tapolab/0.5"}
    ))
    console.print_json(data=result)
    console.print(f"[green]Recon V2 terminée:[/green] {run}")
    return 0


def cmd_recon_capture(args):
    scope, _ = validated_scope()
    run = new_run_dir()

    result = run_recon_with_capture(
        scope,
        run,
        seconds=args.seconds,
        timeout=args.timeout,
        ws_timeout=args.ws_timeout,
        passive_wait=args.passive_wait,
    )

    write_json(run / "recon-capture.json", result)

    if result.get("pcap_summary"):
        write_json(run / "capture-summary.json", result["pcap_summary"])
    if result.get("tcp_conversations"):
        write_json(
            run / "tcp-conversations.json",
            result["tcp_conversations"],
        )

    write_json(run / "manifest.json", build_manifest(
        run, {"tool": "tapolab/0.5-recon-capture"}
    ))

    console.print_json(data={
        "run": str(run),
        "capture": result.get("capture"),
        "pcap_summary": result.get("pcap_summary"),
        "recon_file": str(run / "recon-capture.json"),
        "conversations_file": str(run / "tcp-conversations.json"),
    })
    return 0 if result.get("capture", {}).get("ok") else 3


def cmd_baseline(args):
    scope, ident = validated_scope()
    run = new_run_dir()
    ports = probe_ports(scope.target_ip, scope.tcp_ports, args.timeout)
    rtsp = rtsp_options(scope.target_ip, timeout=args.timeout)
    onvif = onvif_get_device_information(scope.target_ip, timeout=args.timeout)

    write_json(run / "identify.json", ident)
    write_json(run / "ports.json", ports)
    write_json(run / "rtsp.json", rtsp)
    write_json(run / "onvif.json", onvif)
    write_json(run / "summary.json", {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "name": scope.device_name,
            "ip": scope.target_ip,
            "mac": scope.target_mac,
        },
        "open_tcp_ports": [r["port"] for r in ports if r["open"]],
        "rtsp_status_line": rtsp.get("status_line"),
        "onvif_status": onvif.get("status"),
        "onvif_fault": onvif.get("soap_fault"),
    })
    write_json(run / "manifest.json", build_manifest(run))
    console.print(f"[green]Baseline terminée:[/green] {run}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Tapo C200 V5 - lab Python autonome"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("identify")
    p.add_argument("--rediscover", action="store_true")
    p.set_defaults(func=cmd_identify)

    p = sub.add_parser("discover")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("interfaces")
    p.set_defaults(func=cmd_interfaces)

    p = sub.add_parser("ports")
    p.add_argument("--timeout", type=float, default=1.0)
    p.set_defaults(func=cmd_ports)

    p = sub.add_parser("rtsp")
    p.add_argument("--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_rtsp)

    p = sub.add_parser("rtsp-describe")
    p.add_argument("--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_rtsp_describe)

    p = sub.add_parser("onvif")
    p.add_argument("--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_onvif)

    p = sub.add_parser("onvif-matrix")
    p.add_argument("--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_onvif_matrix)

    p = sub.add_parser("ws-discovery")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--local-ip")
    p.set_defaults(func=cmd_ws_discovery)

    p = sub.add_parser("tls")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_tls)

    p = sub.add_parser("probe-8800")
    p.add_argument("--wait", type=float, default=2.0)
    p.set_defaults(func=cmd_probe8800)

    p = sub.add_parser("capture")
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--local-ip")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("analyze")
    p.add_argument("pcap", nargs="?", default="latest")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("conversations")
    p.add_argument("pcap", nargs="?", default="latest")
    p.set_defaults(func=cmd_conversations)

    p = sub.add_parser("baseline")
    p.add_argument("--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("recon-v2")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--ws-timeout", type=float, default=2.0)
    p.add_argument("--passive-wait", type=float, default=2.0)
    p.set_defaults(func=cmd_recon_v2)

    p = sub.add_parser("recon-capture")
    p.add_argument("--seconds", type=int, default=15)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--ws-timeout", type=float, default=2.0)
    p.add_argument("--passive-wait", type=float, default=2.0)
    p.set_defaults(func=cmd_recon_capture)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except ScopeError as exc:
        console.print(f"[bold red]Scope refusé:[/bold red] {exc}")
        return 10
    except FileNotFoundError as exc:
        console.print(f"[bold red]Fichier introuvable:[/bold red] {exc}")
        return 11
    except KeyboardInterrupt:
        return 130
