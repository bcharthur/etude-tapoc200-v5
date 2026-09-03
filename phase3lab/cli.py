from __future__ import annotations

import argparse
from rich.console import Console

from tapolab.config import load_scope
from tapolab.identify import identify
from tapolab.scope import assert_mac_expected, ScopeError
from tapolab.evidence import new_run_dir, write_json, build_manifest

from .credentials import (
    load_credentials,
    credential_status,
    CredentialError,
)
from .rtsp_auth import rtsp_authenticated_matrix
from .onvif_auth import onvif_authenticated_matrix
from .runner import authenticated_capture
from .authdiag import diagnose_auth


console = Console()


def validated_scope():
    scope = load_scope()
    data = identify(scope)
    assert_mac_expected(scope, data.get("observed_mac"))
    return scope


def cmd_doctor(args):
    scope = validated_scope()
    status = credential_status()
    result = {
        "target_ip": scope.target_ip,
        "target_mac": scope.target_mac,
        "credentials": status,
        "ready": status["username_present"] and status["password_present"],
        "note": (
            "Use the local Tapo Camera Account credentials, not TP-Link ID."
        ),
    }
    console.print_json(data=result)
    return 0 if result["ready"] else 2


def cmd_auth_diagnose(args):
    scope = validated_scope()
    creds = load_credentials()
    result = diagnose_auth(
        scope.target_ip,
        creds,
        timeout=args.timeout,
    )
    console.print_json(data=result)
    return 0


def cmd_rtsp_auth(args):
    scope = validated_scope()
    creds = load_credentials()
    result = rtsp_authenticated_matrix(
        scope.target_ip,
        creds,
        also_basic=args.also_basic,
        timeout=args.timeout,
    )
    console.print_json(data=result)
    return 0


def cmd_onvif_auth(args):
    scope = validated_scope()
    creds = load_credentials()
    result = onvif_authenticated_matrix(
        scope.target_ip,
        creds,
        timeout=args.timeout,
    )
    console.print_json(data=result)
    return 0


def cmd_auth_capture(args):
    scope = validated_scope()
    creds = load_credentials()
    run = new_run_dir()

    result = authenticated_capture(
        scope,
        creds,
        run,
        seconds=args.seconds,
        timeout=args.timeout,
    )

    write_json(run / "authenticated-recon.json", result)

    if result.get("pcap_summary") is not None:
        write_json(run / "capture-summary.json", result["pcap_summary"])

    if result.get("tcp_conversations") is not None:
        write_json(run / "tcp-conversations.json", result["tcp_conversations"])

    write_json(
        run / "manifest.json",
        build_manifest(
            run,
            extra={
                "tool": "tapolab-phase3/0.2",
                "target_ip": scope.target_ip,
                "target_mac": scope.target_mac,
                "password_stored": False,
                "rtsp_basic_used": False,
            },
        ),
    )

    console.print_json(data={
        "run": str(run),
        "capture_ok": result.get("capture", {}).get("ok"),
        "pcap_summary": result.get("pcap_summary"),
        "authenticated_recon": str(run / "authenticated-recon.json"),
        "tcp_conversations": str(run / "tcp-conversations.json"),
        "password_stored": False,
        "rtsp_basic_used": False,
    })
    return 0 if result.get("capture", {}).get("ok") else 3


def build_parser():
    parser = argparse.ArgumentParser(
        description="Tapo C200 V5 - Phase 3 authenticated LAN"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser(
        "auth-diagnose",
        help="Tests credentials without capture and validates ONVIF UTC handling",
    )
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_auth_diagnose)

    p = sub.add_parser("rtsp-auth")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--also-basic", action="store_true")
    p.set_defaults(func=cmd_rtsp_auth)

    p = sub.add_parser("onvif-auth")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_onvif_auth)

    p = sub.add_parser("auth-capture")
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_auth_capture)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except CredentialError as exc:
        console.print(f"[bold red]Credentials:[/bold red] {exc}")
        return 20
    except ScopeError as exc:
        console.print(f"[bold red]Scope refusé:[/bold red] {exc}")
        return 10
    except KeyboardInterrupt:
        return 130
