from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

from .camera_scope import load_scope, norm_mac
from .evidence import stamp, write_json


# Public Android-client constants documented by the open-source tapo-cli
# reverse-engineering project. They identify the public mobile app client;
# they are not the user's credentials.
ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
APP_SECRET = "6ed7d97f3e73467f8a5bab90b577ba4c"

GLOBAL_GATEWAY = "https://n-wap-gw.tplinkcloud.com"
APP_TYPE = "TP-Link_Tapo_Android"
APP_VERSION = "2.12.705"

SECRET_KEYS = {
    "token",
    "refreshtoken",
    "cloudpassword",
    "password",
    "accountid",
    "email",
    "mfaemail",
    "cloudusername",
    "nickname",
    "mfaprocessid",
}

SAFE_DEVICE_FIELDS = (
    "deviceType",
    "deviceName",
    "deviceModel",
    "deviceHwVer",
    "fwVer",
    "fwId",
    "hwId",
    "oemId",
    "deviceRegion",
    "isSameRegion",
    "status",
    "appServerUrl",
    "appServerUrlV2",
)

FW_METHODS_READ = [
    {
        "method": "getCloudConfig",
        "params": {"cloud_config": {"name": ["upgrade_info"]}},
    },
    {
        "method": "getFirmwareUpdateStatus",
        "params": {"cloud_config": {"name": "upgrade_status"}},
    },
]

FW_METHOD_TRIGGER = {
    "method": "checkFirmwareVersionByCloud",
    "params": {"cloud_config": {"check_fw_version": "null"}},
}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in SECRET_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def _content_md5(content: str):
    return base64.b64encode(
        hashlib.md5(content.encode("utf-8")).digest()
    ).decode("ascii")


def _signed_headers(content: str, endpoint: str):
    now = str(int(time.time()))
    nonce = str(uuid.uuid4())
    payload = (
        _content_md5(content)
        + "\n"
        + now
        + "\n"
        + nonce
        + "\n"
        + endpoint
    ).encode("utf-8")
    sig = hmac.new(
        APP_SECRET.encode("utf-8"),
        payload,
        hashlib.sha1,
    ).digest().hex()

    return {
        "Content-Md5": _content_md5(content),
        "X-Authorization": (
            f"Timestamp={now}, Nonce={nonce}, "
            f"AccessKey={ACCESS_KEY}, Signature={sig}"
        ),
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": (
            "Tapo CameraClient Android"
            if "/api/v2/common/passthrough" in endpoint
            else "okhttp/3.12.13"
        ),
    }


def _post(base_url, endpoint, payload, *, token=None, timeout=20):
    content = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    url = base_url.rstrip("/") + endpoint
    if token:
        url += "?token=" + token
    res = requests.post(
        url,
        data=content.encode("utf-8"),
        headers=_signed_headers(content, endpoint),
        timeout=timeout,
    )
    res.raise_for_status()
    try:
        return res.json()
    except Exception as exc:
        raise RuntimeError(
            f"Cloud returned non-JSON HTTP {res.status_code}: "
            f"{res.text[:300]!r}"
        ) from exc


def _error_code(obj):
    if not isinstance(obj, dict):
        return 0
    for key in ("error_code", "errorCode"):
        if key in obj:
            try:
                return int(obj[key])
            except Exception:
                return 1
    return 0


def _result(obj):
    if not isinstance(obj, dict):
        return {}
    r = obj.get("result")
    return r if isinstance(r, dict) else {}


def _login_once(base_url, email, password, terminal_uuid):
    endpoint = "/api/v2/account/login"
    payload = {
        "appType": APP_TYPE,
        "appVersion": APP_VERSION,
        "cloudPassword": password,
        "cloudUserName": email,
        "platform": "Android 12",
        "refreshTokenNeeded": False,
        "terminalMeta": "1",
        "terminalName": "V5PatchLab",
        "terminalUUID": terminal_uuid,
    }
    return _post(base_url, endpoint, payload)


def _request_mfa(base_url, email, password, terminal_uuid, mfa_type):
    # Public reverse-engineered names. Email endpoints vary by app generation,
    # so try only this small known set and stop at first success.
    endpoint_sets = {
        1: ["/api/v2/account/getPushVC4TerminalMFA"],
        2: [
            "/api/v2/account/getEmailVC4TerminalMFA",
            "/api/v2/account/sendEmailVC4TerminalMFA",
            "/api/v2/account/getEmailVC4TerminalBind",
            "/api/v2/account/getVC4TerminalMFA",
            "/api/v2/account/getEmailVerifyCode",
        ],
    }
    last = None
    for endpoint in endpoint_sets.get(mfa_type, []):
        payload = {
            "appType": APP_TYPE,
            "cloudPassword": password,
            "cloudUserName": email,
            "terminalUUID": terminal_uuid,
        }
        try:
            out = _post(base_url, endpoint, payload)
        except Exception as exc:
            last = {"endpoint": endpoint, "transport_error": str(exc)}
            continue
        last = {"endpoint": endpoint, "response": redact(out)}
        if _error_code(out) == 0:
            return endpoint, out
    raise RuntimeError(
        "Unable to request MFA code with known endpoint set: "
        + json.dumps(last, ensure_ascii=False)
    )


def login_interactive(*, email=None, mfa_type=None):
    if not email:
        email = input("Tapo account email: ").strip()
    password = getpass.getpass("Tapo account password: ")
    terminal_uuid = uuid.uuid4().hex.upper()

    base_url = GLOBAL_GATEWAY
    obj = _login_once(base_url, email, password, terminal_uuid)

    # Some account generations return the regional entry point in a failed
    # response. Follow it only when it is a TP-Link HTTPS endpoint.
    if _error_code(obj) == -20212:
        r = _result(obj)
        regional = r.get("appServerUrl") or r.get("appServerUrlV2")
        if (
            isinstance(regional, str)
            and regional.startswith("https://")
            and (
                regional.endswith(".tplinkcloud.com")
                or regional.endswith(".tplinknbu.com")
            )
        ):
            base_url = regional
            obj = _login_once(base_url, email, password, terminal_uuid)

    r = _result(obj)

    if "MFAProcessId" in r:
        supported = r.get("supportedMFATypes") or [1]
        if mfa_type is None:
            mfa_type = 2 if 2 in supported else supported[0]
        if mfa_type not in supported:
            raise RuntimeError(
                f"Requested MFA type {mfa_type} not supported; "
                f"camera account reports {supported}"
            )

        _request_mfa(
            base_url,
            email,
            password,
            terminal_uuid,
            int(mfa_type),
        )
        if int(mfa_type) == 1:
            print("Check the Tapo app for the MFA code.")
        else:
            print("Check your email for the MFA code.")
        code = input("MFA code: ").strip()

        endpoint = "/api/v2/account/checkMFACodeAndLogin"
        payload = {
            "appType": APP_TYPE,
            "cloudUserName": email,
            "code": code,
            "MFAProcessId": r["MFAProcessId"],
            "MFAType": int(mfa_type),
            # Keep this transient probe from requesting a remembered terminal.
            "terminalBindEnabled": False,
        }
        obj = _post(base_url, endpoint, payload)
        r = _result(obj)

    if _error_code(obj) != 0 or not r.get("token"):
        raise RuntimeError(
            "Tapo cloud login failed: "
            + json.dumps(redact(obj), ensure_ascii=False)
        )

    app_server = (
        r.get("appServerUrl")
        or r.get("appServerUrlV2")
        or base_url
    )
    return {
        "token": r["token"],
        "app_server": app_server,
        "email_sha256": sha256_text(email.lower()),
        "login_response": redact(obj),
    }


def _device_list(app_server, token):
    endpoint = "/api/v2/common/getDeviceListByPage"
    payload = {
        "deviceTypeList": ["SMART.IPCAMERA"],
        "index": 0,
        "limit": 100,
    }
    obj = _post(app_server, endpoint, payload, token=token)
    if _error_code(obj) != 0:
        raise RuntimeError(
            "Device list failed: "
            + json.dumps(redact(obj), ensure_ascii=False)
        )
    return _result(obj).get("deviceList") or []


def _safe_device(dev):
    out = {
        k: dev.get(k)
        for k in SAFE_DEVICE_FIELDS
        if k in dev
    }
    if dev.get("deviceId"):
        out["deviceId_sha256"] = sha256_text(str(dev["deviceId"]))
    if dev.get("deviceMac"):
        out["deviceMac"] = norm_mac(str(dev["deviceMac"]))
    return out


def _choose_scoped_camera(devices, target_mac):
    wanted = norm_mac(target_mac)
    matches = [
        dev for dev in devices
        if norm_mac(str(dev.get("deviceMac") or "")) == wanted
    ]
    if len(matches) != 1:
        visible = [_safe_device(x) for x in devices]
        raise RuntimeError(
            "Scoped camera MAC did not resolve to exactly one account device. "
            f"target={wanted}, matches={len(matches)}, "
            f"visible_cameras={json.dumps(visible, ensure_ascii=False)}"
        )

    dev = matches[0]
    model = str(dev.get("deviceModel") or dev.get("deviceName") or "")
    hw = str(dev.get("deviceHwVer") or "")
    if "C200" not in model.upper() or not hw.startswith("5"):
        raise RuntimeError(
            "Refusing cloud passthrough because scoped MAC resolved to "
            f"unexpected model/hardware: model={model!r}, hw={hw!r}"
        )
    return dev


def _passthrough(app_server, token, device_id, requests_list):
    endpoint = "/api/v2/common/passthrough"
    payload = {
        "deviceId": device_id,
        "requestData": {
            "method": "multipleRequest",
            "params": {"requests": requests_list},
        },
    }
    obj = _post(app_server, endpoint, payload, token=token)
    if _error_code(obj) != 0:
        raise RuntimeError(
            "Cloud passthrough failed: "
            + json.dumps(redact(obj), ensure_ascii=False)
        )
    return redact(obj)


def _collect_urls(obj):
    out = set()

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str):
            for url in re.findall(r"https://download\.tplinkcloud\.com/[^\s\"'<>]+", x):
                out.add(url.rstrip(".,);]"))

    walk(obj)
    return sorted(out)


def _interesting_fw_fields(obj):
    wanted = {
        "download_url",
        "url",
        "fw_ver",
        "fwver",
        "version",
        "release_note",
        "release_log",
        "release_date",
        "build",
        "file_size",
        "size",
        "md5",
        "sha256",
        "fw_id",
        "fwid",
        "type",
        "location",
        "status",
        "upgrade_status",
    }
    found = []

    def walk(x, path=""):
        if isinstance(x, dict):
            for k, v in x.items():
                p = f"{path}.{k}" if path else str(k)
                if str(k).lower() in wanted and not isinstance(v, (dict, list)):
                    found.append({"path": p, "value": v})
                walk(v, p)
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]")

    walk(obj)
    return found


def _resolve_target_mac(explicit):
    if explicit:
        return norm_mac(explicit)
    try:
        return norm_mac(load_scope()["target_mac"])
    except Exception as exc:
        raise RuntimeError(
            "Target MAC is required. Pass --target-mac or provide "
            "config/scope.json."
        ) from exc


def run_cloud_account_fw_probe(
    *,
    target_mac=None,
    email=None,
    mfa_type=None,
    poll_seconds=20.0,
    interval=2.0,
    trigger=False,
    evidence_base="evidence/runs",
):
    target_mac = _resolve_target_mac(target_mac)
    run_dir = Path(evidence_base) / f"{stamp()}-cloud-account-fw"
    run_dir.mkdir(parents=True, exist_ok=False)

    env_token = os.environ.get("TAPO_TOKEN")
    env_server = os.environ.get("TAPO_APP_SERVER_URL")
    if env_token and env_server:
        session = {
            "token": env_token,
            "app_server": env_server,
            "email_sha256": None,
            "login_response": None,
            "auth_source": "environment",
        }
    else:
        session = login_interactive(
            email=email,
            mfa_type=mfa_type,
        )
        session["auth_source"] = "interactive-login"

    devices = _device_list(
        session["app_server"],
        session["token"],
    )
    dev = _choose_scoped_camera(devices, target_mac)

    timeline = []
    before = _passthrough(
        session["app_server"],
        session["token"],
        dev["deviceId"],
        FW_METHODS_READ,
    )
    timeline.append({
        "ts": utcnow(),
        "phase": "before",
        "response": before,
    })

    trigger_response = None
    if trigger:
        trigger_response = _passthrough(
            session["app_server"],
            session["token"],
            dev["deviceId"],
            [FW_METHOD_TRIGGER],
        )
        timeline.append({
            "ts": utcnow(),
            "phase": "trigger",
            "response": trigger_response,
        })

    deadline = time.monotonic() + max(0.0, float(poll_seconds))
    while trigger and time.monotonic() < deadline:
        time.sleep(max(0.2, float(interval)))
        polled = _passthrough(
            session["app_server"],
            session["token"],
            dev["deviceId"],
            FW_METHODS_READ,
        )
        timeline.append({
            "ts": utcnow(),
            "phase": "poll",
            "response": polled,
        })

    urls = _collect_urls(timeline)
    fields = _interesting_fw_fields(timeline)

    safe_session = {
        "auth_source": session["auth_source"],
        "app_server": session["app_server"],
        "email_sha256": session.get("email_sha256"),
    }

    result = {
        "scope": {
            "target_mac": target_mac,
            "account_camera_match": _safe_device(dev),
        },
        "session": safe_session,
        "trigger_requested": bool(trigger),
        "methods": {
            "read": [x["method"] for x in FW_METHODS_READ],
            "trigger": (
                FW_METHOD_TRIGGER["method"]
                if trigger else None
            ),
            "explicitly_not_sent": [
                "startFirmwareUpgrade",
                "fw_download",
                "upgrade",
                "reboot",
                "factoryReset",
            ],
        },
        "download_tplinkcloud_urls": urls,
        "interesting_firmware_fields": fields,
        "timeline": timeline,
        "evidence": {
            "directory": str(run_dir),
            "result_json": str(run_dir / "result.json"),
        },
        "interpretation": {
            "exact_download_url_recovered": bool(urls),
            "device_fwId": dev.get("fwId"),
            "device_hwId": dev.get("hwId"),
            "device_oemId": dev.get("oemId"),
            "device_fwVer": dev.get("fwVer"),
            "next": (
                "Download the exact URL and continue with decrypt/extract/diff."
                if urls
                else (
                    "No package URL surfaced. Preserve fwId/hwId/oemId and "
                    "upgrade_info; next step is mapping those identifiers to "
                    "firmware metadata or acquiring the package from hardware."
                )
            ),
        },
    }

    write_json(run_dir / "result.json", result)
    return result
