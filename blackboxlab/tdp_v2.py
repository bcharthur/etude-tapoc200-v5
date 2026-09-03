from __future__ import annotations

import binascii
import json
import os
import socket
import struct
import time

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError as exc:
    raise RuntimeError(
        "cryptography is required. Run: "
        "python -m pip install -r blackbox-v0.4-requirements.txt"
    ) from exc


def _make_query():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    payload = json.dumps(
        {"params": {"rsa_key": public_pem}},
        separators=(",", ":"),
    ).encode("utf-8")

    version = 2
    msg_type = 0
    op_code = 1
    msg_size = len(payload)
    flags = 17
    padding_byte = 0
    device_serial = int.from_bytes(os.urandom(4), "big")
    initial_crc = 0x5A6B7C8D

    header = struct.pack(
        ">BBHHBBII",
        version,
        msg_type,
        op_code,
        msg_size,
        flags,
        padding_byte,
        device_serial,
        initial_crc,
    )

    query = bytearray(header + payload)
    crc = binascii.crc32(query).to_bytes(4, "big")
    query[12:16] = crc

    return bytes(query), private_key, {
        "version": version,
        "msg_type": msg_type,
        "op_code": op_code,
        "payload_size": msg_size,
        "flags": flags,
        "device_serial": device_serial,
        "crc32": crc.hex(),
        "query_size": len(query),
        "rsa_key_size": 2048,
    }


def _safe_summary(obj):
    if not isinstance(obj, dict):
        return None

    result = obj.get("result")
    if not isinstance(result, dict):
        return {
            "top_level_keys": sorted(obj.keys()),
            "error_code": obj.get("error_code"),
        }

    encrypt_info = result.get("encrypt_info")
    encrypt_summary = None
    if isinstance(encrypt_info, dict):
        encrypt_summary = {
            "sym_schm": encrypt_info.get("sym_schm"),
            "key_present": bool(encrypt_info.get("key")),
            "key_b64_length": len(encrypt_info.get("key") or ""),
            "data_present": bool(encrypt_info.get("data")),
            "data_b64_length": len(encrypt_info.get("data") or ""),
        }

    mgt = result.get("mgt_encrypt_schm")

    return {
        "error_code": obj.get("error_code"),
        "result_keys": sorted(result.keys()),
        "device_type": result.get("device_type"),
        "device_model": result.get("device_model"),
        "device_name": result.get("device_name"),
        "firmware_version": result.get("firmware_version"),
        "hardware_version": result.get("hardware_version"),
        "ip": result.get("ip"),
        "mac": result.get("mac"),
        "factory_default": result.get("factory_default"),
        "is_reset_wifi": result.get("isResetWiFi"),
        "is_support_iot_cloud": result.get("is_support_iot_cloud"),
        "encrypt_type": result.get("encrypt_type"),
        "mgt_encrypt_schm": mgt,
        "encrypt_info": encrypt_summary,
    }


def tdp_v2_unicast(target_ip: str, timeout: float = 2.0) -> dict:
    query, private_key, query_meta = _make_query()

    results = []

    for port in (20002, 20004):
        started = time.perf_counter()
        item = {
            "port": port,
            "response_received": False,
            "source": None,
            "bytes": 0,
            "header_hex": None,
            "json": None,
            "summary": None,
            "parse_error": None,
            "elapsed_ms": None,
            "error": None,
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (target_ip, port))
                data, addr = s.recvfrom(65535)

            item["response_received"] = True
            item["source"] = {"ip": addr[0], "port": addr[1]}
            item["bytes"] = len(data)
            item["header_hex"] = data[:16].hex()

            if len(data) >= 16:
                payload = data[16:]
                try:
                    obj = json.loads(payload.decode("utf-8"))
                    item["json"] = obj
                    item["summary"] = _safe_summary(obj)
                except Exception as exc:
                    item["parse_error"] = f"{type(exc).__name__}: {exc}"

        except socket.timeout:
            pass
        except OSError as exc:
            item["error"] = f"{type(exc).__name__}: {exc}"

        item["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        results.append(item)

    # Keep the private key only in memory for the duration of this call.
    # v0.4 does not decrypt encrypt_info; it only validates discovery behavior.
    del private_key

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "query": query_meta,
        "ports_tested": [20002, 20004],
        "unicast_only": True,
        "results": results,
        "any_response": any(r["response_received"] for r in results),
        "note": (
            "This uses the modern TDP v2 RSA-public-key discovery shape. "
            "No broadcast is emitted and no encrypted discovery blob is decrypted."
        ),
    }
