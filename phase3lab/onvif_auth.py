from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .credentials import CameraCredentials


SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
PTZ_NS = "http://www.onvif.org/ver20/ptz/wsdl"
TT_NS = "http://www.onvif.org/ver10/schema"

PASSWORD_DIGEST = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
NONCE_BASE64 = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _soap_post(
    ip: str,
    path: str,
    action: str,
    body_xml: str,
    *,
    security_header: str = "",
    timeout: float = 3.0,
) -> dict:
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{SOAP12}">'
        f"<s:Header>{security_header}</s:Header>"
        f"<s:Body>{body_xml}</s:Body>"
        "</s:Envelope>"
    )

    result = {
        "path": path,
        "action": action,
        "status": None,
        "reason": None,
        "headers": {},
        "body": None,
        "soap_fault": None,
        "error": None,
        "elapsed_ms": None,
    }

    started = time.perf_counter()

    try:
        conn = http.client.HTTPConnection(ip, 2020, timeout=timeout)
        conn.request(
            "POST",
            path,
            body=envelope.encode("utf-8"),
            headers={
                "Content-Type": (
                    'application/soap+xml; charset=utf-8; '
                    f'action="{action}"'
                ),
                "User-Agent": "tapolab-phase3/0.2",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        raw = resp.read(262144)

        result["status"] = resp.status
        result["reason"] = resp.reason
        result["headers"] = dict(resp.getheaders())
        result["body"] = raw.decode("utf-8", errors="replace")

        try:
            root = ET.fromstring(raw)
            fault = root.find(f".//{{{SOAP12}}}Fault")
            if fault is not None:
                result["soap_fault"] = " ".join(
                    x.strip()
                    for x in fault.itertext()
                    if x and x.strip()
                )
        except ET.ParseError:
            pass

        conn.close()
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def _child_int(parent: ET.Element, local_name: str) -> int:
    for elem in parent.iter():
        if elem.tag.split("}")[-1] == local_name and elem.text:
            return int(elem.text)
    raise ValueError(local_name)


def _camera_time_info(ip: str, timeout: float) -> dict:
    result = _soap_post(
        ip,
        "/onvif/device_service",
        f"{DEVICE_NS}/GetSystemDateAndTime",
        f'<tds:GetSystemDateAndTime xmlns:tds="{DEVICE_NS}"/>',
        timeout=timeout,
    )

    info = {
        "utc": None,
        "local": None,
        "timezone_text": None,
        "source": "system_clock_fallback",
        "raw_status": result.get("status"),
        "error": result.get("error"),
    }

    body = result.get("body") or ""

    try:
        root = ET.fromstring(body.encode("utf-8"))

        utc_node = None
        local_node = None
        tz_node = None

        for elem in root.iter():
            local = elem.tag.split("}")[-1]
            if local == "UTCDateTime":
                utc_node = elem
            elif local == "LocalDateTime":
                local_node = elem
            elif local == "TZ" and elem.text:
                tz_node = elem.text.strip()

        if utc_node is not None:
            utc = datetime(
                _child_int(utc_node, "Year"),
                _child_int(utc_node, "Month"),
                _child_int(utc_node, "Day"),
                _child_int(utc_node, "Hour"),
                _child_int(utc_node, "Minute"),
                _child_int(utc_node, "Second"),
                tzinfo=timezone.utc,
            )
            info["utc"] = utc
            info["source"] = "camera_UTCDateTime"

        if local_node is not None:
            info["local"] = datetime(
                _child_int(local_node, "Year"),
                _child_int(local_node, "Month"),
                _child_int(local_node, "Day"),
                _child_int(local_node, "Hour"),
                _child_int(local_node, "Minute"),
                _child_int(local_node, "Second"),
            ).isoformat()

        info["timezone_text"] = tz_node

    except Exception as exc:
        info["parse_error"] = f"{type(exc).__name__}: {exc}"

    if info["utc"] is None:
        info["utc"] = datetime.now(timezone.utc)

    info["utc_iso"] = info["utc"].isoformat()
    return info


def _wsse_header(
    creds: CameraCredentials,
    created_dt: datetime,
) -> str:
    nonce = os.urandom(16)
    created = created_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    digest_bytes = hashlib.sha1(
        nonce
        + created.encode("utf-8")
        + creds.password.encode("utf-8")
    ).digest()

    digest = base64.b64encode(digest_bytes).decode("ascii")
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    return (
        f'<wsse:Security xmlns:wsse="{WSSE}" xmlns:wsu="{WSU}" '
        f'xmlns:s="{SOAP12}" s:mustUnderstand="1">'
        '<wsse:UsernameToken>'
        f'<wsse:Username>{_xml_escape(creds.username)}</wsse:Username>'
        f'<wsse:Password Type="{PASSWORD_DIGEST}">{digest}</wsse:Password>'
        f'<wsse:Nonce EncodingType="{NONCE_BASE64}">{nonce_b64}</wsse:Nonce>'
        f'<wsu:Created>{created}</wsu:Created>'
        '</wsse:UsernameToken>'
        '</wsse:Security>'
    )


def _auth_call(
    ip: str,
    creds: CameraCredentials,
    path: str,
    action: str,
    body_xml: str,
    *,
    camera_now: datetime,
    timeout: float,
) -> dict:
    result = _soap_post(
        ip,
        path,
        action,
        body_xml,
        security_header=_wsse_header(creds, camera_now),
        timeout=timeout,
    )
    result["security"] = "WS-Security UsernameToken PasswordDigest <redacted>"
    result["created_utc"] = camera_now.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return result


def _profile_tokens(body: str | None) -> list[str]:
    if not body:
        return []
    try:
        root = ET.fromstring(body.encode("utf-8"))
        tokens = []
        for elem in root.iter():
            if elem.tag.split("}")[-1] in {"Profiles", "Profile"}:
                token = elem.attrib.get("token")
                if token and token not in tokens:
                    tokens.append(token)
        return tokens
    except ET.ParseError:
        return re.findall(r'\btoken="([^"]+)"', body)


def _compact(result: dict) -> dict:
    return {
        "path": result.get("path"),
        "status": result.get("status"),
        "reason": result.get("reason"),
        "soap_fault": result.get("soap_fault"),
        "error": result.get("error"),
        "elapsed_ms": result.get("elapsed_ms"),
        "created_utc": result.get("created_utc"),
    }


def onvif_auth_smoke(
    ip: str,
    creds: CameraCredentials,
    *,
    timeout: float = 3.0,
) -> dict:
    time_info = _camera_time_info(ip, timeout)
    camera_now = time_info["utc"]

    result = _auth_call(
        ip,
        creds,
        "/onvif/service",
        f"{DEVICE_NS}/GetDeviceInformation",
        f'<tds:GetDeviceInformation xmlns:tds="{DEVICE_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    return {
        "target_ip": ip,
        "username": creds.username,
        "password_stored": False,
        "camera_time": {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in time_info.items()
            if k != "utc"
        },
        "result": _compact(result),
        "authenticated": result.get("status") == 200,
    }


def onvif_authenticated_matrix(
    ip: str,
    creds: CameraCredentials,
    *,
    timeout: float = 3.0,
) -> dict:
    time_info = _camera_time_info(ip, timeout)
    camera_now = time_info["utc"]
    path = "/onvif/service"

    calls = {}

    calls["GetDeviceInformation"] = _auth_call(
        ip, creds, path,
        f"{DEVICE_NS}/GetDeviceInformation",
        f'<tds:GetDeviceInformation xmlns:tds="{DEVICE_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    calls["GetProfiles"] = _auth_call(
        ip, creds, path,
        f"{MEDIA_NS}/GetProfiles",
        f'<trt:GetProfiles xmlns:trt="{MEDIA_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    calls["GetVideoEncoderConfigurations"] = _auth_call(
        ip, creds, path,
        f"{MEDIA_NS}/GetVideoEncoderConfigurations",
        f'<trt:GetVideoEncoderConfigurations xmlns:trt="{MEDIA_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    calls["GetAudioEncoderConfigurations"] = _auth_call(
        ip, creds, path,
        f"{MEDIA_NS}/GetAudioEncoderConfigurations",
        f'<trt:GetAudioEncoderConfigurations xmlns:trt="{MEDIA_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    calls["PTZ.GetConfigurations"] = _auth_call(
        ip, creds, path,
        f"{PTZ_NS}/GetConfigurations",
        f'<tptz:GetConfigurations xmlns:tptz="{PTZ_NS}"/>',
        camera_now=camera_now,
        timeout=timeout,
    )

    tokens = _profile_tokens(calls["GetProfiles"].get("body"))
    stream_uris = {}
    snapshot_uris = {}
    ptz_status = {}

    for token in tokens:
        safe = _xml_escape(token)

        stream_uris[token] = _auth_call(
            ip, creds, path,
            f"{MEDIA_NS}/GetStreamUri",
            (
                f'<trt:GetStreamUri xmlns:trt="{MEDIA_NS}" xmlns:tt="{TT_NS}">'
                '<trt:StreamSetup>'
                '<tt:Stream>RTP-Unicast</tt:Stream>'
                '<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
                '</trt:StreamSetup>'
                f'<trt:ProfileToken>{safe}</trt:ProfileToken>'
                '</trt:GetStreamUri>'
            ),
            camera_now=camera_now,
            timeout=timeout,
        )

        snapshot_uris[token] = _auth_call(
            ip, creds, path,
            f"{MEDIA_NS}/GetSnapshotUri",
            (
                f'<trt:GetSnapshotUri xmlns:trt="{MEDIA_NS}">'
                f'<trt:ProfileToken>{safe}</trt:ProfileToken>'
                '</trt:GetSnapshotUri>'
            ),
            camera_now=camera_now,
            timeout=timeout,
        )

        ptz_status[token] = _auth_call(
            ip, creds, path,
            f"{PTZ_NS}/GetStatus",
            (
                f'<tptz:GetStatus xmlns:tptz="{PTZ_NS}">'
                f'<tptz:ProfileToken>{safe}</tptz:ProfileToken>'
                '</tptz:GetStatus>'
            ),
            camera_now=camera_now,
            timeout=timeout,
        )

    return {
        "target_ip": ip,
        "username": creds.username,
        "password_stored": False,
        "camera_time": {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in time_info.items()
            if k != "utc"
        },
        "profile_tokens": tokens,
        "summary": {name: _compact(r) for name, r in calls.items()},
        "stream_uri_summary": {
            token: _compact(r) for token, r in stream_uris.items()
        },
        "snapshot_uri_summary": {
            token: _compact(r) for token, r in snapshot_uris.items()
        },
        "ptz_status_summary": {
            token: _compact(r) for token, r in ptz_status.items()
        },
        "details": calls,
        "stream_uris": stream_uris,
        "snapshot_uris": snapshot_uris,
        "ptz_status": ptz_status,
    }
