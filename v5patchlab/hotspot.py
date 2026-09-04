from __future__ import annotations

import base64
import concurrent.futures
import copy
import getpass
import ipaddress
import json
import socket
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .camera_scope import load_scope, norm_mac, require_setup_scope
from .evidence import stamp, write_json


def _multi(session, method, params):
    return session.send(
        "multipleRequest",
        {
            "requests": [
                {
                    "method": method,
                    "params": params,
                }
            ]
        },
    )


def _first_inner(response):
    try:
        rows = response["result"]["responses"]
        if rows:
            return rows[0]
    except Exception:
        pass
    return response


def _walk(v):
    if isinstance(v, dict):
        yield v
        for x in v.values():
            yield from _walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk(x)


def _find_ap_list_and_key(response):
    ap_lists = []
    public_keys = []

    for node in _walk(response):
        if not isinstance(node, dict):
            continue

        if isinstance(node.get("ap_list"), list):
            ap_lists.append(node["ap_list"])

        scan = node.get("scan")
        if isinstance(scan, dict) and isinstance(scan.get("ap_list"), list):
            ap_lists.append(scan["ap_list"])

        key = node.get("public_key")
        if isinstance(key, str) and "PUBLIC KEY" in key:
            public_keys.append(key)

        if isinstance(scan, dict):
            key = scan.get("public_key")
            if isinstance(key, str) and "PUBLIC KEY" in key:
                public_keys.append(key)

    if not ap_lists:
        raise RuntimeError(
            "scanApList succeeded at transport level but no ap_list "
            "was found in the camera response"
        )

    aps = max(ap_lists, key=len)
    pub = public_keys[0] if public_keys else None
    return aps, pub


def _safe_ap_summary(ap):
    return {
        "ssid": ap.get("ssid"),
        "signal": (
            ap.get("rssi")
            if ap.get("rssi") is not None
            else ap.get("signal")
        ),
        "security": (
            ap.get("key_type")
            or ap.get("auth")
            or ap.get("security")
            or ap.get("encryption")
        ),
        "channel": ap.get("channel"),
    }


def scan_hotspots():
    from .tpap0 import authenticate_default_userpw
    scope, ip, gate = require_setup_scope()
    session = authenticate_default_userpw(ip, scope["target_mac"])

    response = _multi(
        session,
        "scanApList",
        {"onboarding": {"scan": {}}},
    )
    aps, public_key = _find_ap_list_and_key(response)

    return {
        "scope_gate": gate,
        "target_ip": ip,
        "session": session.public_summary(),
        "access_points": [
            _safe_ap_summary(ap)
            for ap in aps
            if isinstance(ap, dict)
        ],
        "count": len(aps),
        "device_public_key_present": bool(public_key),
        "note": (
            "Read-only Wi-Fi scan performed by the scoped camera. "
            "BSSIDs and the device RSA public key are omitted from output."
        ),
    }


def _encrypt_wifi_password(public_key_pem, password):
    try:
        key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
    except Exception as exc:
        raise RuntimeError(
            f"Could not parse onboarding RSA public key: {exc}"
        ) from exc

    ciphertext = key.encrypt(
        password.encode("utf-8"),
        padding.PKCS1v15(),
    )
    return base64.b64encode(ciphertext).decode("ascii")


def connect_hotspot(ssid, *, arm=False):
    from .tpap0 import authenticate_default_userpw
    if not arm:
        raise RuntimeError(
            "connectAp changes the camera Wi-Fi configuration and will "
            "disconnect Tapo_Cam_* when successful. Re-run with --arm."
        )

    scope, ip, gate = require_setup_scope()
    session = authenticate_default_userpw(ip, scope["target_mac"])

    scan_response = _multi(
        session,
        "scanApList",
        {"onboarding": {"scan": {}}},
    )
    aps, public_key = _find_ap_list_and_key(scan_response)

    candidates = [
        ap for ap in aps
        if isinstance(ap, dict)
        and str(ap.get("ssid") or "") == ssid
    ]

    if not candidates:
        visible = sorted({
            str(ap.get("ssid"))
            for ap in aps
            if isinstance(ap, dict) and ap.get("ssid")
        })
        raise RuntimeError(
            f"SSID {ssid!r} not found by the camera. "
            f"Visible SSIDs: {visible!r}. "
            "For an iPhone, enable Personal Hotspot and "
            "'Maximize Compatibility' before retrying."
        )

    def strength(ap):
        value = ap.get("rssi")
        if value is None:
            value = ap.get("signal")
        try:
            return float(value)
        except Exception:
            return -9999.0

    selected = max(candidates, key=strength)

    if not public_key:
        raise RuntimeError(
            "The TPAP onboarding scan returned no dynamic RSA public key. "
            "Refusing to guess or use an unrelated key."
        )

    password = getpass.getpass(f"Hotspot password for {ssid!r}: ")
    if not password:
        raise RuntimeError("Empty hotspot password refused")

    encrypted = _encrypt_wifi_password(public_key, password)
    password = None

    ap_data = copy.deepcopy(selected)
    ap_data["unique_key"] = 1
    ap_data["password"] = encrypted

    started = time.monotonic()
    response = None
    error = None

    try:
        response = _multi(
            session,
            "connectAp",
            {"onboarding": {"connect": ap_data}},
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed = round(time.monotonic() - started, 4)
    inner = _first_inner(response) if response else None
    application_error = (
        inner.get("error_code")
        if isinstance(inner, dict)
        else None
    )

    observations = []
    for i in range(8):
        time.sleep(0.5)
        alive = False
        try:
            with socket.create_connection((ip, 443), timeout=0.3):
                alive = True
        except OSError:
            pass
        observations.append({
            "after_s": round((i + 1) * 0.5, 1),
            "setup_443": alive,
        })

    result = {
        "scope_gate": gate,
        "target_ip_before_handoff": ip,
        "selected_ap": _safe_ap_summary(selected),
        "connect_request_sent": True,
        "transport_response_received": response is not None,
        "transport_error": error,
        "application_error_code": application_error,
        "elapsed_s": elapsed,
        "post_connect_setup_observation": observations,
        "interpretation": {
            "explicit_success": application_error == 0,
            "handoff_possible_without_response": (
                response is None
                and any(not x["setup_443"] for x in observations)
            ),
            "setup_interface_disappeared": any(
                not x["setup_443"] for x in observations
            ),
        },
        "next": (
            f"Connect this PC to {ssid!r}, then run "
            "`python .\\v5patchlab.py hotspot-find`."
        ),
        "credential_handling": {
            "hotspot_password_logged": False,
            "rsa_ciphertext_logged": False,
        },
    }

    run_dir = Path("evidence/runs") / f"{stamp()}-hotspot-connect"
    run_dir.mkdir(parents=True, exist_ok=False)
    result["evidence"] = str(run_dir / "result.json")
    write_json(run_dir / "result.json", result)
    return result


def _current_wifi_network():
    ps = r'''
$ErrorActionPreference = "Stop"
$rows = @()
Get-NetIPConfiguration | ForEach-Object {
  $cfg = $_
  $alias = [string]$cfg.InterfaceAlias
  if ($alias -match 'Wi-Fi|WiFi|WLAN') {
    foreach ($a in @($cfg.IPv4Address)) {
      if ($null -ne $a.IPAddress) {
        $rows += [PSCustomObject]@{
          InterfaceAlias = $alias
          IPAddress = [string]$a.IPAddress
          PrefixLength = [int]$a.PrefixLength
          Gateway = [string](@($cfg.IPv4DefaultGateway.NextHop)[0])
        }
      }
    }
  }
}
$rows | ConvertTo-Json -Depth 4
'''
    cp = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if cp.returncode != 0:
        raise RuntimeError(
            cp.stderr.strip()
            or "Could not inspect current Wi-Fi IPv4 network"
        )

    obj = json.loads(cp.stdout or "[]")
    rows = obj if isinstance(obj, list) else [obj]

    valid = []
    for row in rows:
        ip = row.get("IPAddress")
        prefix = row.get("PrefixLength")
        if not ip or prefix is None:
            continue
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(
                f"{ip}/{int(prefix)}",
                strict=False,
            )
        except Exception:
            continue
        if not addr.is_private:
            continue
        valid.append((row, net))

    if not valid:
        raise RuntimeError(
            "No active private IPv4 Wi-Fi network found. "
            "Connect the PC to the phone hotspot first."
        )

    valid.sort(
        key=lambda x: (
            not bool(x[0].get("Gateway")),
            x[1].num_addresses,
        )
    )
    row, net = valid[0]

    if net.num_addresses > 256:
        raise RuntimeError(
            f"Refusing automatic discovery on large network {net}. "
            "Hotspot discovery is capped at 256 addresses."
        )

    return {
        "interface": row.get("InterfaceAlias"),
        "local_ip": row.get("IPAddress"),
        "prefix_length": row.get("PrefixLength"),
        "gateway": row.get("Gateway"),
        "network": str(net),
    }, net


def find_camera_on_hotspot():
    from .tpap0 import discover
    scope = load_scope()
    expected = norm_mac(scope["target_mac"])
    net_info, net = _current_wifi_network()

    hosts = [str(x) for x in net.hosts()]
    found = []

    def probe(ip):
        try:
            with socket.create_connection((ip, 443), timeout=0.25):
                pass
        except OSError:
            return None

        try:
            d = discover(ip)
        except Exception:
            return None

        mac = norm_mac(
            str(((d.get("result") or {}).get("mac") or ""))
        )
        if mac == expected:
            return {"ip": ip, "discovery": d}
        return None

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(32, max(1, len(hosts)))
    ) as pool:
        for item in pool.map(probe, hosts):
            if item:
                found.append(item)

    if not found:
        return {
            "found": False,
            "network": net_info,
            "expected_mac": expected,
            "note": (
                "The camera was not locally reachable on TCP/443. "
                "Possible causes: connectAp failed, phone hotspot client "
                "isolation, or no DHCP lease."
            ),
        }

    if len(found) > 1:
        raise RuntimeError(
            f"Multiple hosts claimed scoped MAC {expected}: "
            f"{[x['ip'] for x in found]!r}"
        )

    row = found[0]
    return {
        "found": True,
        "network": net_info,
        "expected_mac": expected,
        "target_ip": row["ip"],
        "discovery": row["discovery"],
    }


def cloud_check_on_hotspot(*, poll_seconds=20.0, interval=2.0):
    from .tpap0 import authenticate_default_userpw
    from .cloudcheck import (
        BASELINE_REQUESTS,
        TRIGGER_REQUEST,
        POLL_REQUESTS,
        _safe_send,
        _multi_params,
        _label_multiple,
        extract_metadata,
    )

    located = find_camera_on_hotspot()
    if not located.get("found"):
        return {**located, "cloud_check_run": False}

    ip = located["target_ip"]
    d = located["discovery"]
    scope = load_scope()
    pake = ((d.get("result") or {}).get("tpap") or {}).get("pake") or []

    if 0 not in pake:
        return {
            **located,
            "cloud_check_run": False,
            "reason": (
                f"Camera is reachable but no longer advertises pake:[0] "
                f"(pake={pake!r}). This is useful state information; "
                "do not guess another credential mode."
            ),
        }

    session = authenticate_default_userpw(ip, scope["target_mac"])

    baseline = _safe_send(
        session,
        "multipleRequest",
        _multi_params(BASELINE_REQUESTS),
    )
    trigger = _safe_send(
        session,
        "multipleRequest",
        _multi_params([TRIGGER_REQUEST]),
    )

    trigger_labeled = (
        _label_multiple(trigger["response"], [TRIGGER_REQUEST])
        if trigger["ok"]
        else {}
    )
    trigger_item = trigger_labeled.get(
        "check_firmware_version_by_cloud", {}
    )
    app_error = (
        trigger_item.get("error_code")
        if isinstance(trigger_item, dict)
        else None
    )

    polls = []
    started = time.monotonic()

    while True:
        elapsed = round(time.monotonic() - started, 3)
        call = _safe_send(
            session,
            "multipleRequest",
            _multi_params(POLL_REQUESTS),
        )
        labeled = (
            _label_multiple(call["response"], POLL_REQUESTS)
            if call["ok"]
            else {}
        )
        polls.append({
            "elapsed_s": elapsed,
            "transport_ok": call["ok"],
            "transport_error": call["error"],
            "labeled": labeled,
            "metadata": extract_metadata(call["response"] or {}),
        })

        if elapsed >= poll_seconds:
            break
        time.sleep(
            min(interval, max(0.0, poll_seconds - elapsed))
        )

    aggregate = extract_metadata({
        "baseline": baseline["response"],
        "trigger": trigger["response"],
        "polls": polls,
    })

    urls = [
        x for x in aggregate["urls"]
        if "download.tplinkcloud.com/" in x["url"].lower()
    ]

    result = {
        **located,
        "cloud_check_run": True,
        "auth": {
            "mode": "TPAP default_userpw",
            "pake": pake,
            "session": session.public_summary(),
        },
        "cloud_trigger": {
            "transport_ok": trigger["ok"],
            "transport_error": trigger["error"],
            "application_error_code": app_error,
            "response": trigger["response"],
        },
        "polls": polls,
        "aggregate_metadata": aggregate,
        "download_tplinkcloud_urls": urls,
        "interpretation": {
            "camera_has_hotspot_lan_reachability": True,
            "cloud_check_transport_ok": trigger["ok"],
            "cloud_check_application_success": app_error == 0,
            "firmware_url_found": bool(urls),
            "experiment": (
                "Compare SETUP/no-WAN with unbound-on-WAN while retaining "
                "the same MAC-derived TPAP bootstrap."
            ),
        },
        "safety_note": (
            "No fw_download, install, downgrade, flash, reboot, "
            "or Tapo-account binding request is sent."
        ),
    }

    run_dir = Path("evidence/runs") / f"{stamp()}-hotspot-cloud-check"
    run_dir.mkdir(parents=True, exist_ok=False)
    result["evidence"] = str(run_dir / "result.json")
    write_json(run_dir / "result.json", result)
    return result
