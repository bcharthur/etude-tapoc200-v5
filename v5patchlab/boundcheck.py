from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .boundtpap import (
    BoundAuthError,
    auth_failure_diagnostic,
    authenticate_bound,
    prompt_bound_password,
    register_profile,
)
from .camera_scope import load_scope
from .cloudcheck import (
    POLL_REQUESTS,
    TRIGGER_REQUEST,
    _label_multiple,
    _multi_params,
    extract_metadata,
)
from .evidence import stamp, write_json


READ_BASELINE = [
    {
        "label": "device_info",
        "method": "getDeviceInfo",
        "params": {"device_info": {"name": ["basic_info"]}},
    },
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


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _scope_ip():
    return load_scope()["target_ip"]


def bound_register() -> dict:
    return register_profile(_scope_ip())


def bound_auth_probe(
    *,
    candidate: str,
    password_label: str,
) -> dict:
    ip = _scope_ip()
    password = prompt_bound_password(password_label)

    try:
        try:
            session, diagnostic = authenticate_bound(
                ip,
                password=password,
                candidate=candidate,
            )
        except BoundAuthError as exc:
            failure = auth_failure_diagnostic(exc)
            return {
                "target_ip": ip,
                "authentication": {
                    "ok": False,
                    "candidate": candidate,
                    "candidate_value_logged": False,
                    "credential_value_logged": False,
                    "failure": failure,
                },
                "recommendation": (
                    "Do not make another authentication attempt while the "
                    "server indicates a temporary lockout/cooldown."
                    if failure["temporary_lockout_indicated"]
                    else (
                        "No server-side lockout indicator was exposed. "
                        "This candidate did not authenticate. Test at most one "
                        "different candidate form per invocation."
                    )
                ),
                "note": (
                    "Exactly one candidate was attempted. No automatic retry "
                    "or fallback candidate was sent."
                ),
            }
    finally:
        password = None

    response = session.send(
        "multipleRequest",
        _multi_params([READ_BASELINE[0]]),
    )
    labeled = _label_multiple(response, [READ_BASELINE[0]])

    return {
        "target_ip": ip,
        "authentication": {
            "ok": True,
            **diagnostic,
            "session": session.public_summary(),
        },
        "read_probe": {
            "request": "getDeviceInfo/basic_info",
            "response": labeled.get("device_info"),
        },
        "note": (
            "Exactly one supplied password and one explicit candidate form were "
            "used. The password/derived credential are not logged."
        ),
    }


def bound_cloud_check(
    *,
    candidate: str,
    password_label: str,
    poll_seconds: float = 20.0,
    interval: float = 2.0,
    evidence_base: str = "evidence/runs",
) -> dict:
    if interval < 0.5:
        raise ValueError("interval must be >= 0.5")
    if poll_seconds < 0:
        raise ValueError("poll_seconds must be >= 0")

    ip = _scope_ip()
    password = prompt_bound_password(password_label)

    try:
        try:
            session, diagnostic = authenticate_bound(
                ip,
                password=password,
                candidate=candidate,
            )
        except BoundAuthError as exc:
            failure = auth_failure_diagnostic(exc)
            return {
                "target_ip": ip,
                "authentication": {
                    "ok": False,
                    "candidate": candidate,
                    "candidate_value_logged": False,
                    "credential_value_logged": False,
                    "failure": failure,
                },
                "cloud_check_sent": False,
                "recommendation": (
                    "Wait for the reported server cooldown before any further "
                    "authentication attempt."
                    if failure["temporary_lockout_indicated"]
                    else (
                        "Authentication failed, so no firmware/cloud request "
                        "was sent."
                    )
                ),
            }
    finally:
        password = None

    run_dir = Path(evidence_base) / f"{stamp()}-bound-cloud-check"
    run_dir.mkdir(parents=True, exist_ok=False)
    timeline = run_dir / "timeline.jsonl"

    def append(row):
        with timeline.open("a", encoding="utf-8") as f:
            f.write(json.dumps(
                {"ts": _utc(), **row},
                ensure_ascii=False,
                default=str,
            ) + "\n")

    baseline_response = session.send(
        "multipleRequest",
        _multi_params(READ_BASELINE),
    )
    baseline = _label_multiple(
        baseline_response,
        READ_BASELINE,
    )
    append({
        "phase": "baseline",
        "labeled": baseline,
        "metadata": extract_metadata(baseline_response),
    })

    trigger_response = session.send(
        "multipleRequest",
        _multi_params([TRIGGER_REQUEST]),
    )
    trigger = _label_multiple(
        trigger_response,
        [TRIGGER_REQUEST],
    )
    append({
        "phase": "cloud_trigger",
        "labeled": trigger,
        "metadata": extract_metadata(trigger_response),
    })

    polls = []
    start = time.monotonic()
    previous = None

    while True:
        elapsed = round(time.monotonic() - start, 3)
        response = session.send(
            "multipleRequest",
            _multi_params(POLL_REQUESTS),
        )
        labeled = _label_multiple(response, POLL_REQUESTS)
        canonical = json.dumps(
            labeled,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        row = {
            "elapsed_s": elapsed,
            "labeled": labeled,
            "metadata": extract_metadata(response),
            "sha256": digest,
            "changed": previous is not None and digest != previous,
        }
        polls.append(row)
        append({"phase": "poll", **row})
        previous = digest

        if elapsed >= poll_seconds:
            break
        time.sleep(min(interval, max(0.0, poll_seconds - elapsed)))

    aggregate = extract_metadata({
        "baseline": baseline,
        "trigger": trigger,
        "polls": polls,
    })
    urls = [
        x for x in aggregate["urls"]
        if "download.tplinkcloud.com/" in x["url"].lower()
    ]

    trigger_item = trigger.get(
        "check_firmware_version_by_cloud", {}
    )

    result = {
        "target_ip": ip,
        "authentication": {
            "ok": True,
            **diagnostic,
            "session": session.public_summary(),
        },
        "baseline": baseline,
        "cloud_trigger": trigger,
        "polls": polls,
        "aggregate_metadata": aggregate,
        "download_tplinkcloud_urls": urls,
        "interpretation": {
            "bound_tpap_userpw_authenticated": True,
            "cloud_check_application_error_code": (
                trigger_item.get("error_code")
                if isinstance(trigger_item, dict) else None
            ),
            "firmware_url_found": bool(urls),
            "poll_metadata_changed": any(p["changed"] for p in polls),
        },
        "evidence": {
            "directory": str(run_dir),
            "timeline_jsonl": str(timeline),
            "result_json": str(run_dir / "result.json"),
        },
        "safety_note": (
            "No fw_download/startFirmwareUpgrade/update/downgrade/flash/reboot "
            "request is sent. Password and derived credentials are never stored."
        ),
    }
    write_json(run_dir / "result.json", result)
    return result
