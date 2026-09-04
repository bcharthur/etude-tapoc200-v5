from __future__ import annotations

import getpass
import hashlib
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from .camera_scope import load_scope, norm_mac
from .evidence import stamp, write_json


CHECK_REQUESTS = [
    {
        "label": "check_firmware",
        "method": "checkFirmwareVersionByCloud",
        "params": {"cloud_config": {"check_fw_version": "null"}},
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


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _tcp_open(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _https_discover(ip, timeout=3.0):
    body = b'{"method":"login","params":{"sub_method":"discover"}}'
    req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=None) as s:
            s.sendall(req)
            data = bytearray()
            while len(data) < 131072:
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)

    _, _, payload = bytes(data).partition(b"\r\n\r\n")
    return json.loads(payload.decode("utf-8", errors="replace"))


def _find_scoped_ip():
    scope = load_scope()
    ip = scope["target_ip"]
    expected_mac = norm_mac(scope["target_mac"])

    if not _tcp_open(ip, 443):
        raise RuntimeError(
            f"Scoped NORMAL IP {ip}:443 is not reachable. "
            "Pair the camera back to the normal Wi-Fi first."
        )

    d = _https_discover(ip)
    got = norm_mac(str(((d.get("result") or {}).get("mac") or "")))
    if got != expected_mac:
        raise RuntimeError(
            f"Refusing: discovery MAC {got!r} != scoped MAC {expected_mac!r}"
        )

    return scope, ip, d


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
    out = {
        "urls": [],
        "versions": [],
        "hashes": [],
        "sizes": [],
        "filenames": [],
        "states": [],
    }

    for path, key, value in _walk(obj):
        lk = str(key).lower()

        if isinstance(value, str):
            lv = value.lower()

            if lv.startswith(("http://", "https://")):
                out["urls"].append({"path": path, "url": value})

            if any(x in lk for x in (
                "version", "fw_ver", "firmware", "release", "build"
            )):
                out["versions"].append({"path": path, "value": value})

            if any(x in lk for x in ("md5", "sha1", "sha256", "hash")):
                out["hashes"].append({"path": path, "value": value})

            if any(x in lk for x in (
                "filename", "file_name", "fw_name", "package"
            )):
                out["filenames"].append({"path": path, "value": value})

            if any(x in lk for x in ("state", "status")):
                out["states"].append({"path": path, "value": value})

        elif isinstance(value, (int, float)):
            if any(x in lk for x in ("size", "length", "bytes")):
                out["sizes"].append({"path": path, "value": value})

    return out


def _safe_call(label, fn):
    started = time.monotonic()
    try:
        value = fn()
        return {
            "label": label,
            "ok": True,
            "elapsed_s": round(time.monotonic() - started, 4),
            "result": value,
            "error": None,
        }
    except Exception as exc:
        return {
            "label": label,
            "ok": False,
            "elapsed_s": round(time.monotonic() - started, 4),
            "result": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _multiple_request(tapo, rows):
    return tapo.performRequest({
        "method": "multipleRequest",
        "params": {
            "requests": [
                {"method": r["method"], "params": r["params"]}
                for r in rows
            ]
        },
    })


def _label_responses(response, rows):
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


def _redacted_identity(user):
    return {
        "username_supplied": bool(user),
        "username_sha256": (
            hashlib.sha256(user.encode()).hexdigest()
            if user else None
        ),
        "password_supplied": True,
        "password_logged": False,
    }


def normal_ready():
    scope, ip, d = _find_scoped_ip()
    return {
        "target_ip": ip,
        "expected_mac": norm_mac(scope["target_mac"]),
        "discovery": d,
        "tcp": {
            "443": _tcp_open(ip, 443),
            "554": _tcp_open(ip, 554),
            "2020": _tcp_open(ip, 2020),
            "8800": _tcp_open(ip, 8800),
        },
        "interpretation": {
            "normal_ip_reachable": True,
            "pake": ((d.get("result") or {}).get("tpap") or {}).get("pake"),
            "noc": ((d.get("result") or {}).get("tpap") or {}).get("noc"),
        },
    }


def run_normal_cloud_check(
    *,
    username: str,
    poll_seconds: float = 20.0,
    interval: float = 2.0,
    evidence_base: str = "evidence/runs",
):
    if poll_seconds < 0:
        raise ValueError("poll_seconds must be >= 0")
    if interval < 0.5:
        raise ValueError("interval must be >= 0.5")

    scope, ip, discovery = _find_scoped_ip()

    # Password never enters argparse, environment variables, JSON evidence,
    # stdout, or shell history.
    password = getpass.getpass(
        f"Camera Account password for {username!r}: "
    )

    if not password:
        raise RuntimeError("Empty Camera Account password refused")

    try:
        from pytapo import Tapo
    except ImportError as exc:
        raise RuntimeError(
            "pytapo is not installed. Run: "
            "pip install -r requirements-v5patchlab.txt"
        ) from exc

    run_dir = Path(evidence_base) / f"{stamp()}-normal-cloud-check"
    run_dir.mkdir(parents=True, exist_ok=False)
    timeline = run_dir / "timeline.jsonl"

    def append(row):
        with timeline.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {"ts": _utc_now(), **row},
                    ensure_ascii=False,
                    default=str,
                ) + "\n"
            )

    # Constructing Tapo performs local authentication and getBasicInfo.
    auth = _safe_call(
        "pytapo_auth",
        lambda: Tapo(ip, username, password),
    )

    # Drop the password reference as soon as constructor returns.
    password = None

    if not auth["ok"]:
        result = {
            "target_ip": ip,
            "discovery": discovery,
            "credentials": _redacted_identity(username),
            "authentication": {
                "ok": False,
                "error": auth["error"],
            },
            "next": (
                "Verify Camera Account credentials. If the local Camera "
                "Account does not work on this firmware, pytapo documents "
                "an 'admin' + TP-Link cloud-password fallback; do not try it "
                "unless you explicitly intend to."
            ),
            "evidence": str(run_dir),
        }
        write_json(run_dir / "result.json", result)
        return result

    tapo = auth["result"]

    basic = _safe_call("getBasicInfo", tapo.getBasicInfo)
    fw_status = _safe_call(
        "getFirmwareUpdateStatus",
        tapo.getFirmwareUpdateStatus,
    )

    # Baseline cached upgrade_info before triggering any cloud check.
    cached = _safe_call(
        "cached_upgrade_info",
        lambda: _multiple_request(
            tapo,
            [{
                "label": "upgrade_info",
                "method": "getCloudConfig",
                "params": {
                    "cloud_config": {"name": ["upgrade_info"]}
                },
            }],
        ),
    )

    baseline = {
        "basic_info": basic,
        "firmware_update_status": fw_status,
        "cached_upgrade_info": cached,
    }
    append({
        "phase": "baseline",
        "metadata": extract_metadata(baseline),
        "results": baseline,
    })

    # This check is intentionally NOT the fw_download action.
    trigger_rows = [{
        "label": "check_firmware",
        "method": "checkFirmwareVersionByCloud",
        "params": {
            "cloud_config": {"check_fw_version": "null"}
        },
    }]
    trigger = _safe_call(
        "checkFirmwareVersionByCloud",
        lambda: _multiple_request(tapo, trigger_rows),
    )
    append({
        "phase": "cloud_trigger",
        "result": trigger,
        "metadata": extract_metadata(trigger),
    })

    polls = []
    start = time.monotonic()
    last_hash = None

    poll_rows = [
        {
            "label": "upgrade_info",
            "method": "getCloudConfig",
            "params": {
                "cloud_config": {"name": ["upgrade_info"]}
            },
        },
        {
            "label": "upgrade_status",
            "method": "getFirmwareUpdateStatus",
            "params": {
                "cloud_config": {"name": "upgrade_status"}
            },
        },
    ]

    while True:
        elapsed = round(time.monotonic() - start, 3)
        call = _safe_call(
            "poll",
            lambda: _multiple_request(tapo, poll_rows),
        )
        labeled = (
            _label_responses(call["result"], poll_rows)
            if call["ok"] else {}
        )
        canonical = json.dumps(
            labeled,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()

        row = {
            "elapsed_s": elapsed,
            "transport": {
                "ok": call["ok"],
                "error": call["error"],
                "elapsed_s": call["elapsed_s"],
            },
            "labeled": labeled,
            "metadata": extract_metadata(call["result"] or {}),
            "sha256": digest,
            "changed": last_hash is not None and digest != last_hash,
        }
        polls.append(row)
        append({"phase": "poll", **row})
        last_hash = digest

        if elapsed >= poll_seconds:
            break
        time.sleep(min(interval, max(0, poll_seconds - elapsed)))

    aggregate = extract_metadata({
        "baseline": baseline,
        "trigger": trigger,
        "polls": polls,
    })

    firmware_urls = [
        x for x in aggregate["urls"]
        if "download.tplinkcloud.com/" in x["url"].lower()
    ]

    result = {
        "target_ip": ip,
        "discovery": discovery,
        "credentials": _redacted_identity(username),
        "authentication": {
            "ok": True,
            "library": "pytapo",
        },
        "basic_info": basic["result"] if basic["ok"] else None,
        "firmware_update_status": (
            fw_status["result"] if fw_status["ok"] else None
        ),
        "cached_upgrade_info": (
            cached["result"] if cached["ok"] else None
        ),
        "cloud_trigger": trigger,
        "polls": polls,
        "aggregate_metadata": aggregate,
        "download_tplinkcloud_urls": firmware_urls,
        "interpretation": {
            "normal_lan_management_authenticated": True,
            "cloud_check_call_completed": trigger["ok"],
            "firmware_url_found": bool(firmware_urls),
            "poll_metadata_changed": any(p["changed"] for p in polls),
        },
        "evidence": {
            "directory": str(run_dir),
            "timeline_jsonl": str(timeline),
            "result_json": str(run_dir / "result.json"),
        },
        "safety_note": (
            "No fw_download/startFirmwareUpgrade/update/downgrade/flash/reboot "
            "request is emitted by this command. Camera Account password is "
            "read with getpass and is never written to evidence."
        ),
    }

    write_json(run_dir / "result.json", result)
    return result
