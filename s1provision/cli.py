from __future__ import annotations

import argparse
from rich.console import Console

from tapolab.evidence import new_run_dir, write_json, build_manifest

from .setup_stream import setup_stream_smoke
from .setup_tpap0 import setup_tpap0_register


console = Console()


def cmd_setup_stream(args):
    run = new_run_dir()
    result = setup_stream_smoke(
        timeout=args.timeout,
        max_parts=args.max_parts,
        max_video_bytes=args.max_video_bytes,
    )

    write_json(run / "s1-setup-stream-smoke-v081.json", result)
    write_json(
        run / "manifest.json",
        build_manifest(
            run,
            extra={
                "tool": "tapolab-s1-provisioning/0.8.1",
                "credentials_supplied_by_user": False,
                "authorization_header_sent": False,
                "historical_default_secret_attempted": result.get(
                    "historical_setup_secret_attempted", False
                ),
                "media_saved": False,
                "state_changes_sent": False,
            },
        ),
    )

    console.print_json(data={"run": str(run), "result": result})
    return 0 if not result.get("error") else 2


def cmd_setup_tpap0(args):
    run = new_run_dir()
    result = setup_tpap0_register(timeout=args.timeout)
    write_json(run / "s1-setup-tpap0-register.json", result)
    console.print_json(data={"run": str(run), "result": result})
    return 0 if not result.get("error") else 2


def build_parser():
    p = argparse.ArgumentParser(
        description="Tapo C200 V5 S1 setup research v0.8.1"
    )
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("setup-stream-smoke")
    q.add_argument("--timeout", type=float, default=4.0)
    q.add_argument("--max-parts", type=int, default=8)
    q.add_argument("--max-video-bytes", type=int, default=262144)
    q.set_defaults(func=cmd_setup_stream)

    q = sub.add_parser("setup-tpap0-register")
    q.add_argument("--timeout", type=float, default=2.0)
    q.set_defaults(func=cmd_setup_tpap0)

    return p


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
