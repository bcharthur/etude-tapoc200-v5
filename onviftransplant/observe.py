from __future__ import annotations

import time

from .evidence import EvidenceRun
from .net import tcp_matrix, https_discover
from .runner import verify_identity


def passive_observe(
    *,
    scope,
    ip: str,
    gate: dict,
    seconds: float,
    interval: float,
    evidence_base: str,
    include_discover_every: float = 15.0,
):
    if seconds <= 0:
        raise ValueError("seconds must be > 0")
    if interval < 0.1:
        raise ValueError("interval must be >= 0.1 seconds")

    discovery = verify_identity(scope, ip)
    run = EvidenceRun(evidence_base, "onvif-observe")

    started = time.monotonic()
    end = started + seconds
    next_discover = started
    samples = []
    transitions = []
    last_tcp = None

    run.event(
        "observe_start",
        gate=gate,
        target_ip=ip,
        seconds=seconds,
        interval=interval,
        discovery=discovery,
    )

    print(
        f"[observe] passive monitoring {ip} for {seconds:.1f}s "
        f"at {interval:.2f}s interval; no ONVIF mutation payload is sent.",
        flush=True,
    )

    seq = 0
    while time.monotonic() < end:
        seq += 1
        now = time.monotonic()
        tcp = tcp_matrix(ip)
        elapsed = round(now - started, 3)

        sample = {
            "seq": seq,
            "elapsed_s": elapsed,
            "tcp": tcp,
        }

        if now >= next_discover:
            try:
                sample["discover"] = https_discover(ip)
            except Exception as exc:
                sample["discover_error"] = f"{type(exc).__name__}: {exc}"
            next_discover = now + include_discover_every

        samples.append(sample)

        if tcp != last_tcp:
            transition = {
                "elapsed_s": elapsed,
                "from": last_tcp,
                "to": tcp,
            }
            transitions.append(transition)
            run.event("tcp_transition", **transition)
            print(f"[observe] t={elapsed:7.3f}s tcp={tcp}", flush=True)
            last_tcp = tcp

        time.sleep(interval)

    summary = {
        "scope_gate": gate,
        "target_ip": ip,
        "seconds": seconds,
        "interval": interval,
        "sample_count": len(samples),
        "transitions": transitions,
        "initial_tcp": samples[0]["tcp"] if samples else None,
        "final_tcp": samples[-1]["tcp"] if samples else None,
        "stable": len(transitions) <= 1,
        "evidence_dir": str(run.dir),
        "note": "Passive observation only; no ONVIF mutation request was sent.",
    }

    # Store samples separately to keep summary readable.
    for sample in samples:
        run.event("observe_sample", **sample)
    run.finish(summary)
    return summary


def single_shot(
    *,
    scope,
    ip: str,
    gate: dict,
    body: bytes,
    axis: str,
    value: int,
    path: str,
    evidence_base: str,
    pre_seconds: float,
    post_seconds: float,
    interval: float,
    request_sender,
):
    if interval < 0.1:
        raise ValueError("interval must be >= 0.1")
    if pre_seconds < 1 or post_seconds < 1:
        raise ValueError("pre/post windows must be >=1 second")

    verify_identity(scope, ip)
    run = EvidenceRun(evidence_base, f"onvif-single-{axis}-{value}")

    def sample_window(label: str, duration: float):
        started = time.monotonic()
        end = started + duration
        rows = []
        last = None
        while time.monotonic() < end:
            tcp = tcp_matrix(ip)
            elapsed = round(time.monotonic() - started, 3)
            row = {"window": label, "elapsed_s": elapsed, "tcp": tcp}
            rows.append(row)
            if tcp != last:
                run.event("single_transition", **row)
                print(
                    f"[single:{label}] t={elapsed:7.3f}s tcp={tcp}",
                    flush=True,
                )
                last = tcp
            time.sleep(interval)
        return rows

    print(
        f"[single] PRE passive window {pre_seconds}s. "
        "No mutation payload yet.",
        flush=True,
    )
    pre = sample_window("pre", pre_seconds)

    if not pre or not pre[-1]["tcp"].get("2020"):
        raise RuntimeError(
            "ONVIF was not stable/reachable at the end of PRE window; "
            "single-shot request was NOT sent."
        )

    from .evidence import sha256
    request_hash = sha256(body)

    print(
        f"[single] sending exactly ONE testcase: {axis}={value}, "
        f"body={len(body)}B",
        flush=True,
    )
    run.event(
        "single_request_start",
        axis=axis,
        value=value,
        body_len=len(body),
        body_sha256=request_hash,
        path=path,
        tcp_immediately_before=tcp_matrix(ip),
    )

    started = time.monotonic()
    response = request_sender(ip, path, body)
    request_elapsed = time.monotonic() - started

    run.event(
        "single_request_result",
        axis=axis,
        value=value,
        body_len=len(body),
        body_sha256=request_hash,
        elapsed_s=round(request_elapsed, 4),
        response=response,
        tcp_immediately_after=tcp_matrix(ip),
    )

    print(
        f"[single] request returned status={response.get('status_line')!r}; "
        f"POST passive window {post_seconds}s starts now.",
        flush=True,
    )

    post = sample_window("post", post_seconds)

    # One final identity check if 443 is alive.
    final_tcp = tcp_matrix(ip)
    final_discover = None
    if final_tcp.get("443"):
        try:
            final_discover = https_discover(ip)
        except Exception as exc:
            final_discover = {"error": f"{type(exc).__name__}: {exc}"}

    # Analyze whether 2020 ever disappeared after the request.
    post_2020_down = [
        r for r in post
        if not r["tcp"].get("2020")
    ]
    pre_2020_down = [
        r for r in pre
        if not r["tcp"].get("2020")
    ]

    if post_2020_down and not pre_2020_down:
        causal_signal = "POST_REQUEST_ONVIF_OUTAGE_OBSERVED_PRE_WINDOW_STABLE"
    elif post_2020_down and pre_2020_down:
        causal_signal = "ONVIF_OUTAGES_EXIST_IN_BOTH_PRE_AND_POST_WINDOWS"
    else:
        causal_signal = "NO_ONVIF_OUTAGE_OBSERVED"

    summary = {
        "scope_gate": gate,
        "target_ip": ip,
        "axis": axis,
        "value": value,
        "path": path,
        "body_len": len(body),
        "body_sha256": request_hash,
        "request_response": response,
        "request_elapsed_s": round(request_elapsed, 4),
        "pre_seconds": pre_seconds,
        "post_seconds": post_seconds,
        "interval": interval,
        "pre_samples": len(pre),
        "post_samples": len(post),
        "pre_2020_down_samples": len(pre_2020_down),
        "post_2020_down_samples": len(post_2020_down),
        "first_post_2020_down_s": (
            post_2020_down[0]["elapsed_s"]
            if post_2020_down else None
        ),
        "causal_signal": causal_signal,
        "final_tcp": final_tcp,
        "final_discover": final_discover,
        "evidence_dir": str(run.dir),
        "note": (
            "Exactly one bounded parser testcase. "
            "No shellcode, ROP, command execution or persistence."
        ),
    }

    # Persist all samples.
    for row in pre:
        run.event("single_sample", **row)
    for row in post:
        run.event("single_sample", **row)

    run.finish(summary)
    return summary
