from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import ipaddress

from tapolab.config import load_scope

from .wifi_windows import connected_wifi
from .netstate import ip_configurations


def _private(value):
    try:
        a = ipaddress.ip_address(value)
        return a.version == 4 and a.is_private
    except Exception:
        return False


def _target():
    scope = load_scope()
    wifi = connected_wifi()
    ssid = wifi.get("ssid") or ""

    suffix = scope.target_mac.replace(":", "").replace("-", "")[-4:].upper()
    expected = f"Tapo_Cam_{suffix}"

    if ssid.upper() != expected.upper():
        return None, {
            "ok": False,
            "expected_ssid": expected,
            "actual_ssid": ssid,
            "error": "Not connected to scoped setup SSID.",
        }

    cfg = ip_configurations()
    if not cfg.get("ok"):
        return None, {
            "ok": False,
            "error": cfg.get("error"),
        }

    for row in cfg.get("interfaces") or []:
        alias = (row.get("InterfaceAlias") or "").lower()
        if not any(x in alias for x in ("wi-fi", "wifi", "wlan")):
            continue

        for gw in row.get("IPv4DefaultGateway") or []:
            if gw and _private(gw):
                return gw, {
                    "ok": True,
                    "expected_ssid": expected,
                    "actual_ssid": ssid,
                }

    return None, {
        "ok": False,
        "error": "No private setup gateway.",
    }


def _post(ip, obj, timeout=2.0):
    body = json.dumps(obj, separators=(",", ":")).encode()
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {ip}:443\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "requestByApp: true\r\n"
        "Accept: application/json\r\n"
        "User-Agent: Tapo CameraClient Android\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=None) as s:
            s.sendall(request)

            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data.extend(chunk)

            head, sep, rest = bytes(data).partition(b"\r\n\r\n")
            lines = head.decode("latin-1", errors="replace").splitlines()

            status = lines[0] if lines else None
            headers = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                headers.setdefault(k.strip().lower(), []).append(v.strip())

            length = None
            try:
                vals = headers.get("content-length") or []
                if vals:
                    length = int(vals[-1])
            except Exception:
                pass

            buf = bytearray(rest)
            while length is not None and len(buf) < length:
                chunk = s.recv(min(8192, length - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)

    text = bytes(buf[:length] if length is not None else buf).decode(
        "utf-8", errors="replace"
    )

    parsed = None
    try:
        parsed = json.loads(text)
    except Exception:
        pass

    return {
        "status_line": status,
        "json": parsed,
        "body_preview": None if parsed is not None else text[:2048],
    }


def setup_tpap0_register(timeout=2.0):
    ip, gate = _target()

    out = {
        "scope_gate": gate,
        "target_ip": ip,
        "credentials_used": False,
        "passcode_used": False,
        "pake_share_sent": False,
        "session_created": False,
        "response": None,
        "error": None,
    }

    if not ip:
        out["error"] = gate.get("error")
        return out

    obj = {
        "method": "login",
        "params": {
            "sub_method": "pake_register",
            "username": hashlib.md5(b"admin").hexdigest(),
            "user_random": base64.b64encode(os.urandom(32)).decode(),
            "cipher_suites": [1],
            "encryption": ["aes_128_ccm"],
            "passcode_type": "default_userpw",
            "stok": None,
        },
    }

    try:
        raw = _post(ip, obj, timeout=timeout)
        parsed = raw.get("json")

        result = (
            parsed.get("result", {})
            if isinstance(parsed, dict)
            and isinstance(parsed.get("result"), dict)
            else {}
        )

        out["response"] = {
            "status_line": raw.get("status_line"),
            "error_code": (
                parsed.get("error_code")
                if isinstance(parsed, dict)
                else None
            ),
            "result_keys": sorted(result.keys()),
            "sub_method": result.get("sub_method"),
            "cipher_suites": result.get("cipher_suites"),
            "encryption": result.get("encryption"),
            "iterations": result.get("iterations"),
            "dev_salt_present": bool(result.get("dev_salt")),
            "dev_random_present": bool(result.get("dev_random")),
            "dev_share_present": bool(result.get("dev_share")),
            "extra_crypt_present": bool(result.get("extra_crypt")),
            "raw_json": parsed,
        }

    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"

    return out
