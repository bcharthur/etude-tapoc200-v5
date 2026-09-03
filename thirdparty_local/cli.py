from __future__ import annotations

import argparse
import getpass
import json
import socket
import time

from .netstate import setup_gateway
from .scope import load_scope
from .third_account import enable as enable_third_account
from .tpap0 import discover, authenticate_default_userpw
from .wifi_gate import require_scoped_setup_ssid


def tcp(ip, port, timeout=0.7):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def context():
    gate = require_scoped_setup_ssid()
    ip = setup_gateway()
    scope = load_scope()
    return gate, ip, scope


def cmd_probe(args):
    gate, ip, scope = context()
    result = {
        "scope_gate": gate,
        "target_ip": ip,
        "discovery": discover(ip),
        "tcp": {
            str(port): tcp(ip, port)
            for port in (443, 554, 2020, 8800)
        },
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_handshake(args):
    gate, ip, scope = context()

    print(
        "[thirdparty] TPAP discovery + pake:[0] SPAKE2+...",
        flush=True,
    )
    session = authenticate_default_userpw(
        ip,
        scope.target_mac,
    )

    print(json.dumps({
        "scope_gate": gate,
        "session_established": True,
        "session": session.public_summary(),
        "credentials_supplied_by_user": False,
        "passcode_source": "MAC-derived default_userpw",
        "passcode_printed": False,
    }, indent=2, ensure_ascii=False))
    return 0


def cmd_enable(args):
    if not args.arm:
        raise RuntimeError(
            "This changes third_account state. Re-run with --arm."
        )

    gate, ip, scope = context()

    password = args.password
    if password is None:
        password = getpass.getpass(
            "New RTSP/ONVIF camera-account password: "
        )

    if len(password) < 6:
        raise RuntimeError(
            "Use a camera-account password of at least 6 characters."
        )

    print(
        "[thirdparty] TPAP pake:[0] SPAKE2+ authentication...",
        flush=True,
    )
    session = authenticate_default_userpw(
        ip,
        scope.target_mac,
    )
    print("[thirdparty] TPAP session established.", flush=True)

    print(
        "[thirdparty] sending setAccountEnabled + "
        "changeThirdAccount...",
        flush=True,
    )
    response = enable_third_account(
        session,
        username=args.username,
        password=password,
    )

    time.sleep(0.8)

    print(json.dumps({
        "scope_gate": gate,
        "target_ip": ip,
        "session": session.public_summary(),
        "password_saved": False,
        "password_echoed": False,
        "username": args.username,
        "commands": [
            "setAccountEnabled",
            "changeThirdAccount",
        ],
        "response": response,
        "post_change_tcp": {
            str(port): tcp(ip, port)
            for port in (443, 554, 2020, 8800)
        },
    }, indent=2, ensure_ascii=False))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "C200 V5 local TPAP third-account configurator v1.1"
        )
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    q = sub.add_parser("probe")
    q.set_defaults(func=cmd_probe)

    q = sub.add_parser(
        "handshake",
        help=(
            "Authenticate TPAP pake:[0] only; "
            "no configuration change"
        ),
    )
    q.set_defaults(func=cmd_handshake)

    q = sub.add_parser(
        "enable",
        help="Enable/change RTSP/ONVIF third_account locally",
    )
    q.add_argument("--username", default="tapolab")
    q.add_argument("--password", default=None)
    q.add_argument("--arm", action="store_true")
    q.set_defaults(func=cmd_enable)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"[thirdparty] ERROR: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        return 2
