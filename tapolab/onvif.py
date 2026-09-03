from __future__ import annotations

import http.client
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
PTZ_NS = "http://www.onvif.org/ver20/ptz/wsdl"
TT_NS = "http://www.onvif.org/ver10/schema"

TOKEN_RE = re.compile(r'\btoken="([^"]+)"', re.I)


def _envelope(body_xml: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{SOAP12}">'
        f"<s:Body>{body_xml}</s:Body>"
        "</s:Envelope>"
    )


def _soap_post(ip, port, path, action, body_xml, timeout=2.0):
    body = _envelope(body_xml).encode()
    result = {
        "ip": ip,
        "port": port,
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
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": (
                    'application/soap+xml; charset=utf-8; '
                    f'action="{action}"'
                ),
                "User-Agent": "tapolab/0.5",
                "Connection": "close",
            },
        )

        resp = conn.getresponse()
        raw = resp.read(131072)

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


def _device_call(ip, port, path, method, body="", timeout=2.0):
    return _soap_post(
        ip, port, path,
        f"{DEVICE_NS}/{method}",
        f'<tds:{method} xmlns:tds="{DEVICE_NS}">{body}</tds:{method}>',
        timeout,
    )


def onvif_get_device_information(ip: str, port: int = 2020, timeout: float = 2.0):
    return _device_call(
        ip, port, "/onvif/device_service",
        "GetDeviceInformation",
        timeout=timeout,
    )


def _extract_service_xaddr(get_services: dict) -> str | None:
    body = get_services.get("body")
    if not body:
        return None
    try:
        root = ET.fromstring(body.encode())
        for elem in root.iter():
            if elem.tag.endswith("XAddr") and elem.text:
                value = elem.text.strip()
                if "/onvif/" in value:
                    return value
    except ET.ParseError:
        pass
    return None


def _path_from_xaddr(xaddr: str | None) -> str:
    if not xaddr:
        return "/onvif/service"
    parsed = urlparse(xaddr)
    return parsed.path or "/onvif/service"


def onvif_matrix(ip: str, port: int = 2020, timeout: float = 2.0) -> dict:
    bootstrap_path = "/onvif/device_service"

    services = _device_call(
        ip, port, bootstrap_path, "GetServices",
        "<tds:IncludeCapability>false</tds:IncludeCapability>",
        timeout,
    )
    advertised_xaddr = _extract_service_xaddr(services)
    service_path = _path_from_xaddr(advertised_xaddr)

    tests = [("GetServices", services)]

    read_only_device = [
        ("GetSystemDateAndTime", ""),
        ("GetCapabilities", "<tds:Category>All</tds:Category>"),
        ("GetServiceCapabilities", ""),
        ("GetScopes", ""),
        ("GetHostname", ""),
        ("GetNetworkInterfaces", ""),
        ("GetDNS", ""),
        ("GetNTP", ""),
    ]

    for method, body in read_only_device:
        tests.append((
            method,
            _device_call(ip, port, service_path, method, body, timeout),
        ))

    tests.append((
        "GetDeviceInformation",
        _device_call(
            ip, port, service_path,
            "GetDeviceInformation",
            "",
            timeout,
        ),
    ))

    profiles = _soap_post(
        ip, port, service_path,
        f"{MEDIA_NS}/GetProfiles",
        f'<trt:GetProfiles xmlns:trt="{MEDIA_NS}"/>',
        timeout,
    )
    tests.append(("GetProfiles", profiles))

    token = None
    if profiles.get("body"):
        match = TOKEN_RE.search(profiles["body"])
        if match:
            token = match.group(1)

    if token:
        stream_uri = _soap_post(
            ip, port, service_path,
            f"{MEDIA_NS}/GetStreamUri",
            (
                f'<trt:GetStreamUri xmlns:trt="{MEDIA_NS}" '
                f'xmlns:tt="{TT_NS}">'
                "<trt:StreamSetup>"
                "<tt:Stream>RTP-Unicast</tt:Stream>"
                "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
                "</trt:StreamSetup>"
                f"<trt:ProfileToken>{token}</trt:ProfileToken>"
                "</trt:GetStreamUri>"
            ),
            timeout,
        )
        tests.append(("GetStreamUri", stream_uri))

    ptz = _soap_post(
        ip, port, service_path,
        f"{PTZ_NS}/GetConfigurations",
        f'<tptz:GetConfigurations xmlns:tptz="{PTZ_NS}"/>',
        timeout,
    )
    tests.append(("PTZ.GetConfigurations", ptz))

    summary = []
    for name, result in tests:
        summary.append({
            "method": name,
            "path": result.get("path"),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "soap_fault": result.get("soap_fault"),
            "error": result.get("error"),
            "elapsed_ms": result.get("elapsed_ms"),
        })

    return {
        "ip": ip,
        "port": port,
        "advertised_xaddr": advertised_xaddr,
        "service_path_used": service_path,
        "profile_token_observed": token,
        "summary": summary,
        "details": {name: result for name, result in tests},
    }
