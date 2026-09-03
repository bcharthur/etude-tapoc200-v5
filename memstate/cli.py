from __future__ import annotations

import argparse
from pathlib import Path

from .evidence import new_run, write_json, manifest
from .flash import carve_flash, flash_diff
from .indexer import firmware_index, directory_diff
from .mipsmap import mips_map
from .uart import list_serial_ports, capture_uart, analyze_uart
from .network import snapshot
from .oracle import watch_crash
from .fuzz import rtsp_authorization_fuzz, streamd_boundary_fuzz, https_json_fuzz
from .report import build_state_report, find_latest_state
from .preflight import require_file, require_directory


def _print(obj):
    import json
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def cmd_plan(args):
    _print({
        "important": (
            "NORMAL-state fuzzing requires the scoped target/service to be "
            "reachable. v0.9.1 refuses otherwise."
        ),
        "phase_1": [
            "snapshot SETUP while connected to Tapo_Cam_*",
            "re-pair camera",
            "verify 192.168.1.79 is reachable",
            "snapshot NORMAL",
            "state-report --auto",
        ],
        "phase_2": [
            "attach physical USB-to-TTL UART adapter",
            "capture reset/reboot UART",
            "acquire NORMAL and SETUP SPI NOR dumps",
        ],
        "phase_3": [
            "flash-diff",
            "firmware-index",
            "mips-map",
        ],
        "phase_4": [
            "crash-oracle + bounded fuzz with UART attached",
        ],
    })
    return 0


def cmd_snapshot(args):
    run = new_run("state")
    result = snapshot(args.ip)
    write_json(run / f"state-{args.label}.json", result)

    any_open = any(
        x.get("open") for x in result.get("tcp", {}).values()
    )
    result["snapshot_quality"] = {
        "any_service_open": any_open,
        "warning": (
            None if any_open
            else "No tested service was reachable at the observed IP. "
                 "Do not use this as a valid NORMAL snapshot."
        ),
    }
    write_json(run / f"state-{args.label}.json", result)

    write_json(run / "manifest.json", manifest(
        run,
        tool="memorylab/0.9.1 snapshot",
        extra={"label": args.label},
    ))
    _print({"run": str(run), "result": result})
    return 0 if any_open else 2


def cmd_flash_carve(args):
    require_file(args.dump, "flash dump")
    result = carve_flash(args.dump, args.out, args.map)
    _print(result)
    return 0


def cmd_flash_diff(args):
    require_file(args.before, "before flash dump")
    require_file(args.after, "after flash dump")
    result = flash_diff(
        args.before, args.after, args.out, args.map,
        page_size=args.page_size,
    )
    _print({
        "output": args.out,
        "changed_run_count": result["changed_run_count"],
        "changed_byte_count": result["changed_byte_count"],
        "partition_stats": result["partition_stats"],
    })
    return 0


def cmd_dir_diff(args):
    require_directory(args.before, "before filesystem")
    require_directory(args.after, "after filesystem")
    result = directory_diff(args.before, args.after, args.out)
    _print({
        "output": args.out,
        "changed_entry_count": result["changed_entry_count"],
    })
    return 0


def cmd_index(args):
    root = require_directory(args.root, "firmware root")
    if not any(root.rglob("*")):
        raise RuntimeError(
            f"Firmware root is empty: {root}. Extract the firmware first."
        )
    result = firmware_index(args.root, args.out)
    _print({
        "output": args.out,
        "file_count": result["file_count"],
        "hit_count": result["hit_count"],
    })
    return 0


def cmd_mips(args):
    require_file(args.binary, "MIPS/ELF binary")
    result = mips_map(args.binary, args.out, args.term or None)
    _print({
        "output": args.out,
        "header": result["header"],
        "string_hit_count": len(result.get("string_hits", [])),
        "xref_count": len(result.get("approximate_string_xrefs", [])),
        "symbol_count": len(result.get("interesting_symbols", [])),
    })
    return 0


def cmd_uart_ports(args):
    ports = list_serial_ports()
    _print({
        "ports": ports,
        "note": (
            None if ports
            else "No serial adapter detected. A physical USB-to-TTL adapter "
                 "must be connected before uart-capture can work."
        ),
    })
    return 0


def cmd_uart_capture(args):
    run = new_run("uart")
    raw = run / "uart.jsonl"
    result = capture_uart(args.port, args.baud, args.seconds, str(raw))
    write_json(run / "uart-capture.json", result)
    analysis = analyze_uart(str(raw))
    write_json(run / "uart-analysis.json", analysis)
    write_json(run / "manifest.json", manifest(
        run,
        tool="memorylab/0.9.1 uart",
        extra={"port": args.port, "baud": args.baud},
    ))
    _print({
        "run": str(run),
        "capture": result,
        "analysis": analysis["classification"],
    })
    return 0


def cmd_uart_analyze(args):
    result = analyze_uart(args.log)
    if args.out:
        write_json(Path(args.out), result)
    _print(result)
    return 0


def cmd_oracle(args):
    run = new_run("crash-oracle")
    output = run / "oracle.jsonl"
    result = watch_crash(
        seconds=args.seconds,
        interval=args.interval,
        out_path=str(output),
        verbose=True,
    )
    write_json(run / "oracle-summary.json", result)
    write_json(run / "manifest.json", manifest(
        run,
        tool="memorylab/0.9.1 crash-oracle",
    ))
    _print({"run": str(run), "result": result})
    return 0


def _fuzz_run(name, fn, args):
    run = new_run(name)
    result = fn(arm=args.arm, delay=args.delay)
    write_json(run / f"{name}.json", result)
    write_json(run / "manifest.json", manifest(
        run,
        tool=f"memorylab/0.9.1 {name}",
        extra={
            "armed": args.arm,
            "scope_locked": True,
            "service_preflight_required": True,
            "stop_on_target_down": True,
        },
    ))
    _print({"run": str(run), "result": result})
    return 0


def cmd_rtsp_fuzz(args):
    return _fuzz_run("rtsp-auth-fuzz", rtsp_authorization_fuzz, args)


def cmd_streamd_fuzz(args):
    return _fuzz_run("streamd-boundary-fuzz", streamd_boundary_fuzz, args)


def cmd_https_fuzz(args):
    return _fuzz_run("https-json-fuzz", https_json_fuzz, args)


def cmd_report(args):
    if args.auto:
        normal = str(find_latest_state("NORMAL"))
        setup = str(find_latest_state("SETUP"))
    else:
        if not args.normal or not args.setup:
            raise RuntimeError(
                "Use --auto, or provide both --normal and --setup."
            )
        normal = args.normal
        setup = args.setup

    require_file(normal, "NORMAL snapshot")
    require_file(setup, "SETUP snapshot")

    result = build_state_report(normal, setup, args.out)
    _print(result)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Tapo C200 V5 memory/state mapping lab v0.9.1"
    )
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("plan")
    q.set_defaults(func=cmd_plan)

    q = sub.add_parser("snapshot")
    q.add_argument("--label", required=True)
    q.add_argument("--ip", default=None)
    q.set_defaults(func=cmd_snapshot)

    q = sub.add_parser("flash-carve")
    q.add_argument("dump")
    q.add_argument("--out", required=True)
    q.add_argument("--map", default="config/c200v5_partitions.json")
    q.set_defaults(func=cmd_flash_carve)

    q = sub.add_parser("flash-diff")
    q.add_argument("before")
    q.add_argument("after")
    q.add_argument("--out", required=True)
    q.add_argument("--map", default="config/c200v5_partitions.json")
    q.add_argument("--page-size", type=int, default=4096)
    q.set_defaults(func=cmd_flash_diff)

    q = sub.add_parser("dir-diff")
    q.add_argument("before")
    q.add_argument("after")
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_dir_diff)

    q = sub.add_parser("firmware-index")
    q.add_argument("root")
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_index)

    q = sub.add_parser("mips-map")
    q.add_argument("binary")
    q.add_argument("--out", required=True)
    q.add_argument("--term", action="append", default=[])
    q.set_defaults(func=cmd_mips)

    q = sub.add_parser("uart-ports")
    q.set_defaults(func=cmd_uart_ports)

    q = sub.add_parser("uart-capture")
    q.add_argument("--port", required=True)
    q.add_argument("--baud", type=int, default=115200)
    q.add_argument("--seconds", type=int, default=180)
    q.set_defaults(func=cmd_uart_capture)

    q = sub.add_parser("uart-analyze")
    q.add_argument("log")
    q.add_argument("--out", default=None)
    q.set_defaults(func=cmd_uart_analyze)

    q = sub.add_parser("crash-oracle")
    q.add_argument("--seconds", type=int, default=180)
    q.add_argument("--interval", type=float, default=0.5)
    q.set_defaults(func=cmd_oracle)

    for name, fn in [
        ("rtsp-auth-fuzz", cmd_rtsp_fuzz),
        ("streamd-boundary-fuzz", cmd_streamd_fuzz),
        ("https-json-fuzz", cmd_https_fuzz),
    ]:
        q = sub.add_parser(name)
        q.add_argument("--arm", action="store_true")
        q.add_argument("--delay", type=float, default=0.3)
        q.set_defaults(func=fn)

    q = sub.add_parser("state-report")
    q.add_argument("--auto", action="store_true")
    q.add_argument("--normal", default=None)
    q.add_argument("--setup", default=None)
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_report)

    return p


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[memorylab] ERROR: {type(exc).__name__}: {exc}")
        return 2
