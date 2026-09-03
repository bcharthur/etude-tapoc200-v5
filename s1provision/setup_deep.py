from __future__ import annotations

import json
import secrets
import socket
import ssl
import time
import ipaddress

from .wifi_windows import connected_wifi
from .netstate import ip_configurations
from .probes import tcp_probe, https_discover

from blackboxlab.stream8800 import stream_8800_challenge
from blackboxlab.tdp_decrypt import tdp_decrypt_once


def _private_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
        return addr.version == 4 and addr.is_private
    except ValueError:
        return False


def _pick_wifi_config(configs: list[dict]) -> dict | None:
    for row in configs:
        alias = (row.get("InterfaceAlias") or "").lower()
        if "wi-fi" in alias or "wifi" in alias or "wlan" in alias:
            return row
    return None


def _https_post_json(
    ip: str,
    obj: dict,
    *,
    path: str = "/",
    timeout: float = 2.0,
) -> dict:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Accept: application/json\r\n"
        "User-Agent: tapolab-s1/0.7\r\n"
        "requestByApp: true\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()

    result = {
        "path": path,
        "request_json": obj,
        "status_line": None,
        "tls_version": None,
        "headers": {},
        "json": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None) as s:
                result["tls_version"] = s.version()
                s.sendall(request)

                data = bytearray()
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    data.extend(chunk)

                head, _, rest = bytes(data).partition(b"\r\n\r\n")
                lines = head.decode("latin-1", errors="replace").splitlines()

                if lines:
                    result["status_line"] = lines[0]

                headers = {}
                for line in lines[1:]:
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    headers.setdefault(k.strip().lower(), []).append(v.strip())
                result["headers"] = headers

                length = None
                try:
                    values = headers.get("content-length") or []
                    if values:
                        length = int(values[-1])
                except ValueError:
                    pass

                body_buf = bytearray(rest)
                if length is not None:
                    while len(body_buf) < length:
                        chunk = s.recv(min(8192, length - len(body_buf)))
                        if not chunk:
                            break
                        body_buf.extend(chunk)
                    payload = bytes(body_buf[:length])
                else:
                    payload = bytes(body_buf)

                text = payload.decode("utf-8", errors="replace")
                try:
                    result["json"] = json.loads(text)
                except Exception:
                    result["body_preview"] = text[:2048]

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def legacy_v3_challenge(ip: str, timeout: float = 2.0) -> dict:
    """
    Phase-1 only:
      login(username=admin, encrypt_type=3, cnonce=random)

    No password is used and no digest_passwd is sent.
    """
    cnonce = secrets.token_hex(8).upper()

    raw = _https_post_json(
        ip,
        {
            "method": "login",
            "params": {
                "cnonce": cnonce,
                "encrypt_type": "3",
                "username": "admin",
            },
        },
        timeout=timeout,
    )

    obj = raw.get("json")
    data = {}
    if isinstance(obj, dict):
        result = obj.get("result")
        if isinstance(result, dict):
            maybe_data = result.get("data")
            if isinstance(maybe_data, dict):
                data = maybe_data

    device_confirm = data.get("device_confirm")
    key = data.get("key")
    nonce = data.get("nonce")

    import hashlib

    return {
        "target_ip": ip,
        "password_used": False,
        "second_login_sent": False,
        "session_created": False,
        "cnonce": cnonce,
        "status_line": raw.get("status_line"),
        "tls_version": raw.get("tls_version"),
        "outer_error_code": obj.get("error_code") if isinstance(obj, dict) else None,
        "challenge": {
            "code": data.get("code"),
            "time": data.get("time"),
            "max_time": data.get("max_time"),
            "encrypt_type": data.get("encrypt_type"),
            "nonce": nonce,
            "nonce_length": len(nonce) if isinstance(nonce, str) else None,
            "key_present": bool(key),
            "key_length": len(key) if isinstance(key, str) else None,
            "device_confirm_present": bool(device_confirm),
            "device_confirm_length": (
                len(device_confirm) if isinstance(device_confirm, str) else None
            ),
            "device_confirm_sha256": (
                hashlib.sha256(device_confirm.encode()).hexdigest()
                if isinstance(device_confirm, str)
                else None
            ),
        },
        "error": raw.get("error"),
        "elapsed_ms": raw.get("elapsed_ms"),
    }


def setup_deep_probe(
    *,
    timeout: float = 2.0,
    baseline_aes_sha256: str | None = None,
) -> dict:
    wifi = connected_wifi()
    ssid = wifi.get("ssid") or ""

    output = {
        "connected_wifi": wifi,
        "authorized_setup_network": False,
        "candidate_camera_ip": None,
        "tcp": None,
        "https_discover": None,
        "legacy_v3_phase1": None,
        "stream8800_challenge": None,
        "tdp_decrypt": None,
        "aes_comparison": None,
        "error": None,
    }

    if not ssid.lower().startswith("tapo_cam_"):
        output["error"] = (
            "Current Wi-Fi is not Tapo_Cam_*. "
            "No setup-state probes were sent."
        )
        return output

    output["authorized_setup_network"] = True

    configs = ip_configurations()
    if not configs.get("ok"):
        output["error"] = configs.get("error")
        return output

    wifi_cfg = _pick_wifi_config(configs.get("interfaces") or [])
    if not wifi_cfg:
        output["error"] = "Could not identify Wi-Fi interface."
        return output

    gateways = wifi_cfg.get("IPv4DefaultGateway") or []
    ip = next((x for x in gateways if _private_ipv4(x)), None)

    if not ip:
        output["error"] = "No private Wi-Fi default gateway found."
        return output

    output["candidate_camera_ip"] = ip

    output["tcp"] = {
        str(port): tcp_probe(ip, port, timeout=0.8)
        for port in (80, 443, 554, 2020, 8800)
    }

    if output["tcp"]["443"]["open"]:
        output["https_discover"] = https_discover(ip, timeout=timeout)
        output["legacy_v3_phase1"] = legacy_v3_challenge(ip, timeout=timeout)

    if output["tcp"]["8800"]["open"]:
        output["stream8800_challenge"] = stream_8800_challenge(
            ip, timeout=timeout
        )

    try:
        tdp = tdp_decrypt_once(
            ip,
            timeout=timeout,
            show_values=False,
        )
        output["tdp_decrypt"] = tdp

        current = None
        crypto = tdp.get("crypto") if isinstance(tdp, dict) else None
        if isinstance(crypto, dict):
            current = crypto.get("aes_material_sha256")

        if baseline_aes_sha256:
            output["aes_comparison"] = {
                "baseline_sha256": baseline_aes_sha256.lower(),
                "setup_sha256": current,
                "same_as_pre_reset": (
                    isinstance(current, str)
                    and current.lower() == baseline_aes_sha256.lower()
                ),
            }
        else:
            output["aes_comparison"] = {
                "baseline_sha256": None,
                "setup_sha256": current,
                "same_as_pre_reset": None,
            }

    except Exception as exc:
        output["tdp_decrypt"] = {
            "error": f"{type(exc).__name__}: {exc}"
        }

    return output
