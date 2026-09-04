from __future__ import annotations

from .camera_scope import require_setup_scope, norm_mac


CAMERA_READ_REQUESTS = [
    {
        "label": "device_info",
        "method": "getDeviceInfo",
        "params": {
            "device_info": {
                "name": ["basic_info"],
            }
        },
    },
    {
        "label": "upgrade_info",
        "method": "getCloudConfig",
        "params": {
            "cloud_config": {
                "name": ["upgrade_info"],
            }
        },
    },
    {
        "label": "firmware_update_status",
        "method": "getFirmwareUpdateStatus",
        "params": {
            "cloud_config": {
                "name": "upgrade_status",
            }
        },
    },
    {
        "label": "firmware_auto_upgrade",
        "method": "getFirmwareAutoUpgradeConfig",
        "params": {
            "auto_upgrade": {
                "name": ["common"],
            }
        },
    },
    {
        "label": "clock_status_control",
        "method": "getClockStatus",
        "params": {
            "system": {
                "name": "clock_status",
            }
        },
    },
]

REFRESH_REQUEST = {
    "label": "firmware_cloud_refresh",
    "method": "checkFirmwareVersionByCloud",
    "params": {
        "cloud_config": {
            "check_fw_version": "null",
        }
    },
}


def _urls(obj):
    out = []

    def walk(v, path=""):
        if isinstance(v, dict):
            for k, x in v.items():
                np = f"{path}.{k}" if path else str(k)
                if isinstance(x, str) and x.lower().startswith(
                    ("http://", "https://")
                ):
                    out.append({"path": np, "url": x})
                walk(x, np)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]")

    walk(obj)
    return out


def _interesting(obj):
    wanted = {
        "download_url", "fw_ver", "fw_id", "fwid", "version",
        "build", "release_note", "release_log", "release_date",
        "md5", "sha256", "size", "file_size", "upgrade_status",
    }
    out = []

    def walk(v, path=""):
        if isinstance(v, dict):
            for k, x in v.items():
                np = f"{path}.{k}" if path else str(k)
                if str(k).lower() in wanted and not isinstance(x, (dict, list)):
                    out.append({"path": np, "value": x})
                walk(x, np)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]")

    walk(obj)
    return out


def _multiple(rows):
    return {
        "requests": [
            {
                "method": row["method"],
                "params": row["params"],
            }
            for row in rows
        ]
    }


def _label_responses(response: dict, rows) -> dict:
    values = (
        ((response.get("result") or {}).get("responses"))
        if isinstance(response, dict)
        else None
    )

    if not isinstance(values, list):
        return {
            "_raw": response,
            "_note": "No result.responses array in camera multipleRequest response.",
        }

    labeled = {}
    for idx, item in enumerate(values):
        label = (
            rows[idx]["label"]
            if idx < len(rows)
            else f"response_{idx}"
        )
        labeled[label] = item
    return labeled


def query_setup_camera(*, refresh=False):
    """
    No Tapo account / no Camera Account password.

    This uses the already-proven SETUP-state TPAP pake:[0] bootstrap session,
    whose credential is deterministically derived from the scoped device MAC.
    """
    from .tpap0 import authenticate_default_userpw, discover

    scope, ip, gate = require_setup_scope()

    d = discover(ip)
    got = str(((d.get("result") or {}).get("mac") or ""))
    if norm_mac(got) != norm_mac(scope["target_mac"]):
        raise RuntimeError(
            f"Discovery MAC {got!r} != scoped MAC {scope['target_mac']!r}"
        )

    session = authenticate_default_userpw(ip, scope["target_mac"])

    refresh_response = None
    refresh_transport = None

    if refresh:
        try:
            refresh_response = session.send(
                "multipleRequest",
                _multiple([REFRESH_REQUEST]),
            )
            refresh_transport = {"ok": True, "error": None}
        except Exception as exc:
            refresh_transport = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

    try:
        response = session.send(
            "multipleRequest",
            _multiple(CAMERA_READ_REQUESTS),
        )
        transport = {"ok": True, "error": None}
    except Exception as exc:
        response = None
        transport = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    labeled = (
        _label_responses(response, CAMERA_READ_REQUESTS)
        if response is not None
        else {}
    )

    urls = _urls(response or {})
    interesting = _interesting(response or {})

    return {
        "scope_gate": gate,
        "target_ip": ip,
        "discovery": d,
        "session": session.public_summary(),
        "authentication": {
            "tapo_account_used": False,
            "camera_account_used": False,
            "user_password_used": False,
            "setup_bootstrap": "TPAP pake:[0] default_userpw derived from scoped MAC",
        },
        "refresh": {
            "requested": bool(refresh),
            "transport": refresh_transport,
            "response": refresh_response,
            "note": (
                "checkFirmwareVersionByCloud only. This cannot work if the "
                "factory-reset camera has no upstream Internet connectivity."
                if refresh
                else "Not requested."
            ),
        },
        "read_transport": transport,
        "request": {
            "method": "multipleRequest",
            "read_request_count": len(CAMERA_READ_REQUESTS),
            "requests": CAMERA_READ_REQUESTS,
        },
        "response": response,
        "labeled_responses": labeled,
        "urls_found": urls,
        "interesting_firmware_fields": interesting,
        "interpretation": {
            "transport_ok": transport["ok"],
            "upgrade_info_returned": "upgrade_info" in labeled,
            "firmware_update_status_returned": (
                "firmware_update_status" in labeled
            ),
            "url_returned": bool(urls),
            "next": (
                "Use the exact returned public firmware URL."
                if urls
                else (
                    "No URL cached in SETUP. Continue with the public 1.4.2 "
                    "vulnerable baseline now; obtain exact 1.4.6 later from "
                    "the device flash/UART."
                )
            ),
        },
        "note": (
            "No account login is performed. No firmware install/download, "
            "downgrade, flash, reboot, reset, or configuration write is sent."
        ),
    }
