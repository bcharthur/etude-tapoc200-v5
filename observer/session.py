from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from memstate.evidence import manifest, new_run, write_json
from memstate.network import snapshot
from memstate.scope import load_scope

from .common import append_jsonl, build_rtsp_url, load_env_file, monotonic, redact_url, runtime_info, safe_label, utc_now_iso
from .network_probe import NetworkProbe
from .pcap import PcapCapture
from .report import build_report
from .rtsp_probe import RtspProbe
from .state_probe import StateSampler
from .tapo_probe import TapoProbe
from .timeline import Timeline
from .wifi_probe import WifiScanner


ACTIVE_FILE = Path("evidence/.observer-active.json")


def _active_obj(run: Path, start_mono: float, start_wall: float, label: str) -> dict:
    return {
        "run": str(run.resolve()),
        "start_monotonic": start_mono,
        "start_wall_epoch": start_wall,
        "label": label,
        "pid": os.getpid(),
        "created_utc": utc_now_iso(),
    }


def mark_active(text: str, kind: str = "MARK") -> dict:
    if not ACTIVE_FILE.exists():
        raise RuntimeError("No active observer session. Start observerlab.py observe first.")
    info = json.loads(ACTIVE_FILE.read_text(encoding="utf-8"))
    run = Path(info["run"])
    t = round(monotonic() - float(info["start_monotonic"]), 6)
    obj = {
        "t": t,
        "utc": utc_now_iso(),
        "source": "operator",
        "event": kind.upper(),
        "text": text,
    }
    append_jsonl(run / "markers.jsonl", obj)
    return {"run": str(run), "marker": obj}


def observe(*, label: str, seconds: float, ip: str | None, interval: float, wifi_interval: float, state_interval: float, tapo_interval: float, rtsp_heartbeat: float, ports: list[int], env_file: str | None, enable_wifi: bool, enable_rtsp: bool, enable_tapo: bool, pcap_interface: str | None, pcap_filter: str | None, capture_backend: str = "auto") -> tuple[Path, dict]:
    load_env_file(env_file)
    scope = load_scope()
    target = ip or scope.target_ip
    run = new_run(f"observe-{safe_label(label)}")
    start_mono = monotonic()
    start_wall = time.time()
    timeline = Timeline(run / "timeline.jsonl", start_mono)
    stop_event = threading.Event()

    rtsp_url = build_rtsp_url(target) if enable_rtsp else None
    effective_pcap_filter = pcap_filter if pcap_filter is not None else (f"host {target}" if pcap_interface else None)

    config = {
        "label": label,
        "target_ip": target,
        "target_mac": scope.target_mac,
        "scope_source": scope.source,
        "seconds": seconds,
        "interval": interval,
        "wifi_interval": wifi_interval,
        "state_interval": state_interval,
        "tapo_interval": tapo_interval,
        "ports": ports,
        "wifi_enabled": enable_wifi,
        "rtsp_requested": enable_rtsp,
        "rtsp_configured": bool(rtsp_url),
        "rtsp_url": redact_url(rtsp_url),
        "tapo_requested": enable_tapo,
        "tapo_configured": bool(os.getenv("TAPO_USER") and os.getenv("TAPO_PASSWORD")),
        "pcap_interface": pcap_interface,
        "pcap_filter": effective_pcap_filter,
        "capture_backend": capture_backend,
        "runtime": runtime_info(),
    }
    write_json(run / "experiment.json", config)
    ACTIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACTIVE_FILE.write_text(json.dumps(_active_obj(run, start_mono, start_wall, label), indent=2), encoding="utf-8")

    timeline.emit("experiment", "START", label=label, target_ip=target, target_mac=scope.target_mac)
    try:
        before = snapshot(target)
        write_json(run / "state-before.json", before)
        timeline.emit("state", "BEFORE_CAPTURED")
    except Exception as exc:
        timeline.emit("state", "BEFORE_ERROR", error=f"{type(exc).__name__}: {exc}")

    probes: list[threading.Thread] = [
        NetworkProbe(ip=target, ports=ports, interval=interval, timeline=timeline, run=run, stop_event=stop_event),
        StateSampler(ip=target, interval=state_interval, timeline=timeline, run=run, stop_event=stop_event),
    ]
    if enable_wifi:
        probes.append(WifiScanner(interval=wifi_interval, timeline=timeline, run=run, stop_event=stop_event, target_mac=scope.target_mac))
    if enable_rtsp:
        probes.append(RtspProbe(url=rtsp_url, timeline=timeline, run=run, stop_event=stop_event, heartbeat=rtsp_heartbeat))
    if enable_tapo:
        probes.append(TapoProbe(ip=target, interval=tapo_interval, timeline=timeline, run=run, stop_event=stop_event))

    pcap = PcapCapture(
        run=run,
        timeline=timeline,
        interface=pcap_interface,
        capture_filter=effective_pcap_filter,
        target_ip=target,
        backend=capture_backend,
    )
    pcap.start()
    for probe in probes:
        probe.start()

    deadline = start_mono + seconds if seconds > 0 else None
    interrupted = False
    try:
        while not stop_event.is_set():
            if deadline is not None and monotonic() >= deadline:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        interrupted = True
        timeline.emit("experiment", "INTERRUPT")
    finally:
        stop_event.set()
        for probe in probes:
            probe.join(timeout=5.0)
        pcap.stop()
        try:
            after = snapshot(target)
            write_json(run / "state-after.json", after)
            timeline.emit("state", "AFTER_CAPTURED")
        except Exception as exc:
            timeline.emit("state", "AFTER_ERROR", error=f"{type(exc).__name__}: {exc}")
        timeline.emit("experiment", "STOP", interrupted=interrupted)
        try:
            if ACTIVE_FILE.exists():
                active = json.loads(ACTIVE_FILE.read_text(encoding="utf-8"))
                if Path(active.get("run", "")) == run.resolve():
                    ACTIVE_FILE.unlink()
        except Exception:
            pass

    report = build_report(run)
    write_json(run / "manifest.json", manifest(run, tool="observerlab/1.1.0", extra={"label": label, "target_ip": target}))
    return run, report
