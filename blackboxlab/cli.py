from __future__ import annotations

import argparse
from rich.console import Console

from tapolab.evidence import new_run_dir, write_json, build_manifest

from .common import validated_scope
from .rtsp_regression import run_rtsp_loopback_regression
from .stream8800 import stream_8800_challenge, stream_8800_preauth_preview_probe
from .https443 import https_443_preauth_discovery
from .rtsp_methods import rtsp_method_matrix
from .stream8800_v2 import stream_8800_route_matrix, stream_8800_nonce_profile
from .https443_v2 import https_443_oracle_matrix
from .tpap_register import tpap_register_probe
from .tdp20002 import tdp_20002_unicast
from .rtsp_teardown import characterize_teardown
from .tpap_profile import tpap_register_profile
from .tpap_paths import tpap_path_matrix
from .tdp_v2 import tdp_v2_unicast
from .tdp_decrypt import tdp_decrypt_once, tdp_decrypt_profile


console = Console()


def scope():
    s, _ = validated_scope()
    return s


def show(data):
    console.print_json(data=data)
    return 0


def cmd_rtsp_regression(args):
    s = scope()
    return show(run_rtsp_loopback_regression(s.target_ip, timeout=args.timeout))


def cmd_rtsp_methods(args):
    s = scope()
    return show(rtsp_method_matrix(s.target_ip, timeout=args.timeout))


def cmd_rtsp_teardown(args):
    s = scope()
    return show(characterize_teardown(s.target_ip, timeout=args.timeout))


def cmd_8800_challenge(args):
    s = scope()
    return show(stream_8800_challenge(s.target_ip, timeout=args.timeout))


def cmd_8800_preauth(args):
    s = scope()
    return show(stream_8800_preauth_preview_probe(s.target_ip, timeout=args.timeout))


def cmd_8800_routes(args):
    s = scope()
    return show(stream_8800_route_matrix(s.target_ip, timeout=args.timeout))


def cmd_8800_nonces(args):
    s = scope()
    return show(stream_8800_nonce_profile(
        s.target_ip,
        count=args.count,
        timeout=args.timeout,
    ))


def cmd_443_discover(args):
    s = scope()
    return show(https_443_preauth_discovery(s.target_ip, timeout=args.timeout))


def cmd_443_oracle(args):
    s = scope()
    return show(https_443_oracle_matrix(s.target_ip, timeout=args.timeout))


def cmd_tpap_register(args):
    s = scope()
    return show(tpap_register_probe(s.target_ip, timeout=args.timeout))


def cmd_tdp_old(args):
    s = scope()
    return show(tdp_20002_unicast(s.target_ip, timeout=args.timeout))


def cmd_tpap_profile(args):
    s = scope()
    return show(tpap_register_profile(
        s.target_ip,
        count=args.count,
        timeout=args.timeout,
    ))


def cmd_tpap_paths(args):
    s = scope()
    return show(tpap_path_matrix(s.target_ip, timeout=args.timeout))


def cmd_tdp_v2(args):
    s = scope()
    return show(tdp_v2_unicast(s.target_ip, timeout=args.timeout))


def cmd_tdp_decrypt(args):
    s = scope()
    return show(tdp_decrypt_once(
        s.target_ip,
        timeout=args.timeout,
        show_values=args.show_values,
    ))


def cmd_tdp_decrypt_profile(args):
    s = scope()
    return show(tdp_decrypt_profile(
        s.target_ip,
        count=args.count,
        timeout=args.timeout,
    ))


def cmd_sweep5(args):
    s = scope()
    run = new_run_dir()

    result = {
        "scenario": "unauthenticated_LAN_blackbox_surface_v0.5",
        "target": {
            "ip": s.target_ip,
            "mac": s.target_mac,
        },
        "credentials_used": False,
        "password_used": False,
        "pake_share_sent": False,
        "destructive_tests": False,
        "tests": {
            "tdp_decrypt_redacted": tdp_decrypt_once(
                s.target_ip,
                timeout=args.timeout,
                show_values=False,
            ),
            "tdp_decrypt_profile": tdp_decrypt_profile(
                s.target_ip,
                count=args.count,
                timeout=args.timeout,
            ),
        },
        "candidate_findings": [],
        "classification_notes": [
            (
                "TDP encrypt_info decryption is performed using the ephemeral RSA "
                "private key corresponding to the public key intentionally supplied "
                "in the discovery request."
            ),
            (
                "Decrypted discovery metadata is treated as a pre-auth information "
                "surface, not automatically as a vulnerability."
            ),
        ],
    }

    write_json(run / "blackbox-v0.5.json", result)
    write_json(
        run / "manifest.json",
        build_manifest(
            run,
            extra={
                "tool": "tapolab-blackbox/0.5",
                "target_ip": s.target_ip,
                "target_mac": s.target_mac,
                "credentials_used": False,
                "password_used": False,
                "pake_share_sent": False,
                "destructive_tests": False,
                "decrypted_sensitive_values_persisted": False,
            },
        ),
    )

    console.print_json(data=result)
    console.print(f"[green]Run:[/green] {run}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Tapo C200 V5 - black-box/pre-auth lab"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_timeout(p, default=2.0):
        p.add_argument("--timeout", type=float, default=default)

    p = sub.add_parser("rtsp-regression")
    add_timeout(p)
    p.set_defaults(func=cmd_rtsp_regression)

    p = sub.add_parser("rtsp-methods")
    add_timeout(p)
    p.set_defaults(func=cmd_rtsp_methods)

    p = sub.add_parser("rtsp-teardown")
    add_timeout(p)
    p.set_defaults(func=cmd_rtsp_teardown)

    p = sub.add_parser("8800-challenge")
    add_timeout(p)
    p.set_defaults(func=cmd_8800_challenge)

    p = sub.add_parser("8800-preauth")
    add_timeout(p)
    p.set_defaults(func=cmd_8800_preauth)

    p = sub.add_parser("8800-routes")
    add_timeout(p)
    p.set_defaults(func=cmd_8800_routes)

    p = sub.add_parser("8800-nonces")
    add_timeout(p)
    p.add_argument("--count", type=int, default=8)
    p.set_defaults(func=cmd_8800_nonces)

    p = sub.add_parser("443-discover")
    add_timeout(p, 3.0)
    p.set_defaults(func=cmd_443_discover)

    p = sub.add_parser("443-oracle")
    add_timeout(p, 3.0)
    p.set_defaults(func=cmd_443_oracle)

    p = sub.add_parser("tpap-register")
    add_timeout(p, 3.0)
    p.set_defaults(func=cmd_tpap_register)

    p = sub.add_parser("tdp-20002")
    add_timeout(p)
    p.set_defaults(func=cmd_tdp_old)

    p = sub.add_parser("tpap-profile")
    add_timeout(p, 3.0)
    p.add_argument("--count", type=int, default=6)
    p.set_defaults(func=cmd_tpap_profile)

    p = sub.add_parser("tpap-paths")
    add_timeout(p, 3.0)
    p.set_defaults(func=cmd_tpap_paths)

    p = sub.add_parser("tdp-v2")
    add_timeout(p)
    p.set_defaults(func=cmd_tdp_v2)

    p = sub.add_parser("tdp-decrypt")
    add_timeout(p)
    p.add_argument(
        "--show-values",
        action="store_true",
        help=(
            "Print decrypted discovery values including local SSID/owner metadata. "
            "Do not use for evidence you plan to share."
        ),
    )
    p.set_defaults(func=cmd_tdp_decrypt)

    p = sub.add_parser("tdp-decrypt-profile")
    add_timeout(p)
    p.add_argument("--count", type=int, default=4)
    p.set_defaults(func=cmd_tdp_decrypt_profile)

    p = sub.add_parser("sweep-v5")
    add_timeout(p)
    p.add_argument("--count", type=int, default=4)
    p.set_defaults(func=cmd_sweep5)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except RuntimeError as exc:
        console.print(f"[bold red]Runtime:[/bold red] {exc}")
        return 30
    except KeyboardInterrupt:
        return 130
