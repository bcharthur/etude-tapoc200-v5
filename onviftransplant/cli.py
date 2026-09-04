from __future__ import annotations

import argparse
import json

from .http import post_xml
from .net import tcp_matrix
from .offline import index_binary, compare
from .observe import passive_observe, single_shot
from .runner import baseline, run_sweep, verify_identity, choose_baseline_path
from .scope import select_target
from .soap import prefix_case, element_case


def emit(o):
    print(json.dumps(o, indent=2, ensure_ascii=False, default=str))


def cmd_probe(a):
    scope, ip, gate = select_target(a.state)
    discovery = verify_identity(scope, ip)
    matrix = tcp_matrix(ip)
    emit({
        "scope_gate": gate,
        "target_ip": ip,
        "discovery": discovery,
        "tcp": matrix,
        "baseline": baseline(ip) if matrix.get("2020") else None,
    })
    return 0


def cmd_observe(a):
    scope, ip, gate = select_target(a.state)
    emit(passive_observe(
        scope=scope,
        ip=ip,
        gate=gate,
        seconds=a.seconds,
        interval=a.interval,
        evidence_base=a.evidence,
        include_discover_every=a.discover_every,
    ))
    return 0


def cmd_single(a):
    if not a.arm:
        raise RuntimeError(
            "The single testcase may crash/restart ONVIF. Re-run with --arm."
        )

    scope, ip, gate = select_target(a.state)
    discovery = verify_identity(scope, ip)
    matrix = tcp_matrix(ip)

    if not matrix.get("2020"):
        raise RuntimeError("ONVIF :2020 is not reachable; request not sent.")

    base = baseline(ip)
    path = choose_baseline_path(base)

    if a.axis == "elements":
        body = element_case(a.value, a.value_len)
    else:
        body = prefix_case(a.value)

    emit(single_shot(
        scope=scope,
        ip=ip,
        gate=gate,
        body=body,
        axis=a.axis,
        value=a.value,
        path=path,
        evidence_base=a.evidence,
        pre_seconds=a.pre_seconds,
        post_seconds=a.post_seconds,
        interval=a.interval,
        request_sender=post_xml,
    ))
    return 0


def cmd_sweep(a):
    if not a.arm:
        raise RuntimeError(
            "Mutation tests can crash/reboot the scoped camera. "
            "Re-run with --arm."
        )

    scope, ip, gate = select_target(a.state)
    emit(run_sweep(
        scope,
        ip,
        gate,
        a.axis,
        a.profile,
        a.evidence,
        a.delay,
        a.recovery_seconds,
    ))
    return 0


def cmd_index(a):
    emit(index_binary(a.binary))
    return 0


def cmd_compare(a):
    emit(compare(a.a, a.b))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description=(
            "C200 V5 bounded ONVIF vulnerability-transplant harness "
            "(CVE-2025-8065 research) v1.0.1"
        )
    )
    s = p.add_subparsers(dest="command", required=True)

    q = s.add_parser("probe")
    q.add_argument("--state", choices=["normal", "setup"], required=True)
    q.set_defaults(func=cmd_probe)

    q = s.add_parser(
        "observe",
        help="Passive high-resolution service observation; sends no mutation payload.",
    )
    q.add_argument("--state", choices=["normal", "setup"], required=True)
    q.add_argument("--seconds", type=float, default=180.0)
    q.add_argument("--interval", type=float, default=0.25)
    q.add_argument("--discover-every", type=float, default=15.0)
    q.add_argument("--evidence", default="evidence/runs")
    q.set_defaults(func=cmd_observe)

    q = s.add_parser(
        "single",
        help="Send exactly one bounded testcase after a passive PRE window.",
    )
    q.add_argument("--state", choices=["normal", "setup"], required=True)
    q.add_argument("--axis", choices=["prefix", "elements"], required=True)
    q.add_argument("--value", type=int, required=True)
    q.add_argument("--value-len", type=int, default=100)
    q.add_argument("--pre-seconds", type=float, default=30.0)
    q.add_argument("--post-seconds", type=float, default=120.0)
    q.add_argument("--interval", type=float, default=0.25)
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--arm", action="store_true")
    q.set_defaults(func=cmd_single)

    q = s.add_parser("sweep")
    q.add_argument("--state", choices=["normal", "setup"], required=True)
    q.add_argument("--axis", choices=["prefix", "elements"], required=True)
    q.add_argument(
        "--profile",
        choices=["conservative", "extended"],
        default="conservative",
    )
    q.add_argument("--delay", type=float, default=0.8)
    q.add_argument("--recovery-seconds", type=int, default=60)
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--arm", action="store_true")
    q.set_defaults(func=cmd_sweep)

    q = s.add_parser("binary-index")
    q.add_argument("binary")
    q.set_defaults(func=cmd_index)

    q = s.add_parser("binary-compare")
    q.add_argument("a")
    q.add_argument("b")
    q.set_defaults(func=cmd_compare)

    return p


def main():
    a = build_parser().parse_args()
    try:
        return a.func(a)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(
            f"[onviflab] ERROR: {type(e).__name__}: {e}",
            flush=True,
        )
        return 2
