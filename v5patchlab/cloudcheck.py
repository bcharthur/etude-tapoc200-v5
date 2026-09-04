from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .camera_scope import require_setup_scope, norm_mac
from .evidence import stamp, write_json


BASELINE_REQUESTS = [
    {
        "label": "device_info",
        "method": "getDeviceInfo",
        "params": {"device_info": {"name": ["basic_info"]}},
    },
    {
        "label": "upgrade_info_before",
        "method": "getCloudConfig",
        "params": {"cloud_config": {"name": ["upgrade_info"]}},
    },
    {
        "label": "upgrade_status_before",
        "method": "getFirmwareUpdateStatus",
        "params": {"cloud_config": {"name": "upgrade_status"}},
    },
    {
        "label": "clock_status",
        "method": "getClockStatus",
        "params": {"system": {"name": "clock_status"}},
    },
]

TRIGGER_REQUEST = {
    "label": "check_firmware_version_by_cloud",
    "method": "checkFirmwareVersionByCloud",
    "params": {"cloud_config": {"check_fw_version": "null"}},
}

POLL_REQUESTS = [
    {
        "label": "upgrade_info",
        "method": "getCloudConfig",
        "params": {"cloud_config": {"name": ["upgrade_info"]}},
    },
    {
        "label": "upgrade_status",
        "method": "getFirmwareUpdateStatus",
        "params": {"cloud_config": {"name": "upgrade_status"}},
    },
]


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _multi_params(rows):
    return {
        "requests": [
            {"method": row["method"], "params": row["params"]}
            for row in rows
        ]
    }


def _label_multiple(response, rows):
    arr = (
        ((response or {}).get("result") or {}).get("responses")
        if isinstance(response, dict)
        else None
    )
    if not isinstance(arr, list):
        return {"_raw": response}

    out = {}
    for i, item in enumerate(arr):
        label = rows[i]["label"] if i < len(rows) else f"response_{i}"
        out[label] = item
    return out


def _walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, k, v
            yield from _walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]"
            yield p, str(i), v
            yield from _walk(v, p)


def extract_metadata(obj):
    urls = []
    versions = []
    hashes = []
    sizes = []
    filenames = []
    states = []

    for path, key, value in _walk(obj):
        lkey = str(key).lower()

        if isinstance(value, str):
            low = value.lower()
            if low.startswith(("http://", "https://")):
                urls.append({"path": path, "url": value})

            if any(x in lkey for x in (
                "version", "fw_ver", "firmware", "release", "build"
            )):
                if value and len(value) <= 512:
                    versions.append({"path": path, "value": value})

            if any(x in lkey for x in ("md5", "sha1", "sha256", "hash")):
                if value and len(value) <= 512:
                    hashes.append({"path": path, "value": value})

            if any(x in lkey for x in ("file", "filename", "fw_name", "package")):
                if value and len(value) <= 1024:
                    filenames.append({"path": path, "value": value})

            if any(x in lkey for x in ("state", "status")):
                if value and len(value) <= 512:
                    states.append({"path": path, "value": value})

        elif isinstance(value, (int, float)):
            if any(x in lkey for x in ("size", "length", "bytes")):
                sizes.append({"path": path, "value": value})

    def unique(rows):
        seen = set()
        out = []
        for r in rows:
            key = json.dumps(r, sort_keys=True, ensure_ascii=False)
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out

    return {
        "urls": unique(urls),
        "versions": unique(versions),
        "hashes": unique(hashes),
        "sizes": unique(sizes),
        "filenames": unique(filenames),
        "states": unique(states),
    }


def _canonical_hash(obj):
    data = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _append_jsonl(path: Path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def _safe_send(session, method, params):
    started = time.monotonic()
    try:
        response = session.send(method, params)
        return {
            "ok": True,
            "elapsed_s": round(time.monotonic() - started, 4),
            "response": response,
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "elapsed_s": round(time.monotonic() - started, 4),
            "response": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _basic_info_from(labeled):
    try:
        return (
            labeled["device_info"]["result"]["device_info"]["basic_info"]
        )
    except Exception:
        return {}


def _clock_build_observation(basic_info, labeled):
    sw = str(basic_info.get("sw_version") or "")
    clock = ""
    try:
        clock = str(
            labeled["clock_status"]["result"]["system"]["clock_status"][
                "local_time"
            ]
        )
    except Exception:
        pass

    # Example Build 260709 => 2026-07-09.
    import re
    m = re.search(r"\bBuild\s+(\d{6})\b", sw)
    if not m or not clock:
        return {
            "available": False,
            "firmware_build_date": None,
            "camera_local_date": clock[:10] if clock else None,
            "same_date": None,
        }

    token = m.group(1)
    yy, mm, dd = token[:2], token[2:4], token[4:6]
    build_date = f"20{yy}-{mm}-{dd}"
    camera_date = clock[:10]
    return {
        "available": True,
        "firmware_build_date": build_date,
        "camera_local_date": camera_date,
        "same_date": build_date == camera_date,
        "note": (
            "Same-date is an observation only; it does not by itself prove "
            "how the camera initializes its RTC."
        ),
    }


def run_cloud_check(
    *,
    poll_seconds: float = 20.0,
    interval: float = 2.0,
    evidence_base: str = "evidence/runs",
    trigger: bool = True,
):
    if poll_seconds < 0:
        raise ValueError("poll_seconds must be >= 0")
    if interval < 0.5:
        raise ValueError("interval must be >= 0.5 seconds")

    from .tpap0 import authenticate_default_userpw, discover

    scope, ip, gate = require_setup_scope()

    discovery = discover(ip)
    got = str(((discovery.get("result") or {}).get("mac") or ""))
    if norm_mac(got) != norm_mac(scope["target_mac"]):
        raise RuntimeError(
            f"Discovery MAC {got!r} != scoped MAC {scope['target_mac']!r}"
        )

    session = authenticate_default_userpw(ip, scope["target_mac"])

    run_dir = Path(evidence_base) / f"{stamp()}-cloud-check"
    run_dir.mkdir(parents=True, exist_ok=False)
    timeline_path = run_dir / "timeline.jsonl"

    # Baseline is intentionally read-only and is captured before the cloud
    # version-check method, so stale/cached upgrade_info can be distinguished
    # from data that appears after the trigger.
    baseline_send = _safe_send(
        session,
        "multipleRequest",
        _multi_params(BASELINE_REQUESTS),
    )
    baseline_labeled = (
        _label_multiple(baseline_send["response"], BASELINE_REQUESTS)
        if baseline_send["ok"]
        else {}
    )
    baseline_meta = extract_metadata(baseline_send["response"] or {})

    _append_jsonl(timeline_path, {
        "ts": _utc_now(),
        "phase": "baseline",
        "transport": {
            "ok": baseline_send["ok"],
            "elapsed_s": baseline_send["elapsed_s"],
            "error": baseline_send["error"],
        },
        "labeled": baseline_labeled,
        "metadata": baseline_meta,
    })

    basic_info = _basic_info_from(baseline_labeled)

    trigger_send = {
        "ok": None,
        "elapsed_s": 0,
        "response": None,
        "error": None,
        "skipped": not trigger,
    }
    if trigger:
        trigger_send = _safe_send(
            session,
            "multipleRequest",
            _multi_params([TRIGGER_REQUEST]),
        )
        trigger_labeled = (
            _label_multiple(trigger_send["response"], [TRIGGER_REQUEST])
            if trigger_send["ok"]
            else {}
        )
        _append_jsonl(timeline_path, {
            "ts": _utc_now(),
            "phase": "cloud_trigger",
            "transport": {
                "ok": trigger_send["ok"],
                "elapsed_s": trigger_send["elapsed_s"],
                "error": trigger_send["error"],
            },
            "labeled": trigger_labeled,
            "metadata": extract_metadata(trigger_send["response"] or {}),
        })

    polls = []
    start = time.monotonic()
    poll_index = 0
    previous_hash = _canonical_hash(baseline_labeled)

    # Always take an immediate post-trigger/read sample, even poll_seconds=0.
    while True:
        elapsed = time.monotonic() - start
        poll_index += 1

        sample_send = _safe_send(
            session,
            "multipleRequest",
            _multi_params(POLL_REQUESTS),
        )
        sample_labeled = (
            _label_multiple(sample_send["response"], POLL_REQUESTS)
            if sample_send["ok"]
            else {}
        )
        meta = extract_metadata(sample_send["response"] or {})
        current_hash = _canonical_hash(sample_labeled)

        row = {
            "index": poll_index,
            "elapsed_s": round(elapsed, 3),
            "transport": {
                "ok": sample_send["ok"],
                "elapsed_s": sample_send["elapsed_s"],
                "error": sample_send["error"],
            },
            "labeled": sample_labeled,
            "metadata": meta,
            "changed_since_previous": current_hash != previous_hash,
            "canonical_sha256": current_hash,
        }
        polls.append(row)
        _append_jsonl(timeline_path, {
            "ts": _utc_now(),
            "phase": "poll",
            **row,
        })
        previous_hash = current_hash

        if elapsed >= poll_seconds:
            break
        sleep_for = min(interval, max(0.0, poll_seconds - elapsed))
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)

    # Aggregate metadata across baseline, trigger, and polling.
    combined = {
        "baseline": baseline_send["response"],
        "trigger": trigger_send.get("response"),
        "polls": [p["labeled"] for p in polls],
    }
    aggregate = extract_metadata(combined)

    tp_link_urls = [
        row for row in aggregate["urls"]
        if "download.tplinkcloud.com/" in row["url"].lower()
    ]

    trigger_response = trigger_send.get("response") or {}
    trigger_labeled = (
        _label_multiple(trigger_response, [TRIGGER_REQUEST])
        if trigger_send.get("ok")
        else {}
    )
    trigger_item = trigger_labeled.get(
        "check_firmware_version_by_cloud", {}
    )
    trigger_error_code = (
        trigger_item.get("error_code")
        if isinstance(trigger_item, dict)
        else None
    )

    summary = {
        "scope_gate": gate,
        "target_ip": ip,
        "discovery": discovery,
        "session": session.public_summary(),
        "settings": {
            "trigger_cloud_check": trigger,
            "poll_seconds": poll_seconds,
            "interval": interval,
        },
        "baseline": {
            "transport_ok": baseline_send["ok"],
            "transport_error": baseline_send["error"],
            "labeled": baseline_labeled,
            "metadata": baseline_meta,
        },
        "cloud_trigger": {
            "sent": trigger,
            "transport_ok": trigger_send.get("ok"),
            "transport_error": trigger_send.get("error"),
            "application_error_code": trigger_error_code,
            "response": trigger_response,
        },
        "polls": polls,
        "aggregate_metadata": aggregate,
        "download_tplinkcloud_urls": tp_link_urls,
        "device": {
            "model": basic_info.get("device_model"),
            "hw_version": basic_info.get("hw_version"),
            "sw_version": basic_info.get("sw_version"),
            "region": basic_info.get("region"),
            "clock_build_observation": _clock_build_observation(
                basic_info, baseline_labeled
            ),
        },
        "interpretation": {
            "tpap_transport_worked": bool(baseline_send["ok"]),
            "cloud_check_method_transport_worked": (
                bool(trigger_send.get("ok")) if trigger else None
            ),
            "cloud_check_application_success": (
                trigger_error_code == 0
                if trigger_error_code is not None
                else None
            ),
            "exact_firmware_url_found": bool(tp_link_urls),
            "metadata_changed_during_polling": any(
                p["changed_since_previous"] for p in polls
            ),
            "possible_setup_no_wan": (
                bool(trigger)
                and trigger_send.get("ok") is True
                and trigger_error_code not in (None, 0)
                and not tp_link_urls
            ),
        },
        "evidence": {
            "directory": str(run_dir),
            "timeline_jsonl": str(timeline_path),
            "result_json": str(run_dir / "result.json"),
        },
        "safety_note": (
            "The only non-read request is checkFirmwareVersionByCloud, which "
            "asks the camera to check firmware metadata with the vendor cloud. "
            "No fw_download, upgrade, downgrade, flash, reboot, or configuration "
            "write method is sent."
        ),
    }

    write_json(run_dir / "result.json", summary)
    return summary
