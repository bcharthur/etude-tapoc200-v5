from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import socket
import struct
import time

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _make_query():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_pem = private_key.public_key().public_bytes(
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
        "op_code": op_code,
        "flags": flags,
        "device_serial": device_serial,
        "payload_size": msg_size,
        "query_size": len(query),
        "crc32": crc.hex(),
    }


def _decrypt_encrypt_info(private_key, encrypt_info: dict) -> tuple[dict, dict]:
    encrypted_key = base64.b64decode(encrypt_info["key"])
    encrypted_data = base64.b64decode(encrypt_info["data"])

    key_and_iv = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    if len(key_and_iv) < 32:
        raise ValueError(
            f"Discovery RSA plaintext too short: {len(key_and_iv)} bytes"
        )

    key = key_and_iv[:16]
    iv = key_and_iv[16:32]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    ).decryptor()

    padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()

    text = plain.decode("utf-8")
    obj = json.loads(text)

    crypto_meta = {
        "rsa_padding": "OAEP-SHA1/MGF1-SHA1",
        "aes_mode": "AES-128-CBC",
        "key_length": len(key),
        "iv_length": len(iv),
        "wrapped_plaintext_length": len(key_and_iv),
        "aes_material_sha256": hashlib.sha256(key + iv).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(encrypted_data).hexdigest(),
        "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
        "plaintext_length": len(plain),
    }

    return obj, crypto_meta


def _redacted(obj: dict) -> dict:
    result = {}
    for key, value in obj.items():
        if key == "connect_ssid":
            result[key] = "<redacted-ssid>" if value else value
        elif key in {"owner", "device_id"}:
            if isinstance(value, str) and value:
                result[key] = f"<redacted:{len(value)} chars>"
            else:
                result[key] = value
        else:
            result[key] = value
    return result


def _receive(target_ip: str, timeout: float = 2.0) -> dict:
    query, private_key, query_meta = _make_query()

    started = time.perf_counter()
    result = {
        "target_ip": target_ip,
        "port": 20002,
        "credentials_used": False,
        "query": query_meta,
        "response_received": False,
        "source": None,
        "outer": None,
        "decrypted": None,
        "decrypted_redacted": None,
        "decrypted_keys": [],
        "crypto": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (target_ip, 20002))
            data, addr = s.recvfrom(65535)

        result["response_received"] = True
        result["source"] = {"ip": addr[0], "port": addr[1]}

        if len(data) < 16:
            raise ValueError(f"TDP response too short: {len(data)}")

        outer = json.loads(data[16:].decode("utf-8"))
        result["outer"] = outer

        info = outer.get("result", {}).get("encrypt_info")
        if not isinstance(info, dict):
            raise ValueError("No encrypt_info object in TDP response")

        decrypted, crypto_meta = _decrypt_encrypt_info(private_key, info)

        result["decrypted"] = decrypted
        result["decrypted_redacted"] = _redacted(decrypted)
        result["decrypted_keys"] = sorted(decrypted.keys())
        result["crypto"] = crypto_meta

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def tdp_decrypt_once(
    target_ip: str,
    *,
    timeout: float = 2.0,
    show_values: bool = False,
) -> dict:
    raw = _receive(target_ip, timeout)

    output = {
        "target_ip": target_ip,
        "credentials_used": False,
        "response_received": raw["response_received"],
        "source": raw["source"],
        "decrypted_keys": raw["decrypted_keys"],
        "decrypted_data": (
            raw["decrypted"]
            if show_values
            else raw["decrypted_redacted"]
        ),
        "show_values": show_values,
        "crypto": raw["crypto"],
        "elapsed_ms": raw["elapsed_ms"],
        "error": raw["error"],
        "note": (
            "The AES key/IV are never printed or saved. "
            "Only hashes of ephemeral discovery cryptographic material are reported."
        ),
    }

    return output


def tdp_decrypt_profile(
    target_ip: str,
    *,
    count: int = 4,
    timeout: float = 2.0,
) -> dict:
    samples = []

    for _ in range(count):
        raw = _receive(target_ip, timeout)

        decrypted = raw.get("decrypted") or {}
        crypto = raw.get("crypto") or {}

        samples.append({
            "ok": raw.get("response_received") and raw.get("error") is None,
            "elapsed_ms": raw.get("elapsed_ms"),
            "decrypted_keys": sorted(decrypted.keys()),
            "aes_material_sha256": crypto.get("aes_material_sha256"),
            "ciphertext_sha256": crypto.get("ciphertext_sha256"),
            "plaintext_sha256": crypto.get("plaintext_sha256"),
            "connect_type": decrypted.get("connect_type"),
            "http_port": decrypted.get("http_port"),
            "sd_status": decrypted.get("sd_status"),
            "connect_ssid_present": bool(decrypted.get("connect_ssid")),
            "owner_present": bool(decrypted.get("owner")),
            "device_id_present": bool(decrypted.get("device_id")),
        })

    def vals(key):
        return [s[key] for s in samples if s.get(key) is not None]

    aes_hashes = vals("aes_material_sha256")
    ciphertext_hashes = vals("ciphertext_sha256")
    plaintext_hashes = vals("plaintext_sha256")

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "sample_count": len(samples),
        "analysis": {
            "all_successful": bool(samples) and all(s["ok"] for s in samples),
            "unique_aes_material_count": len(set(aes_hashes)),
            "aes_material_stable": bool(aes_hashes) and len(set(aes_hashes)) == 1,
            "unique_ciphertext_count": len(set(ciphertext_hashes)),
            "ciphertext_stable": (
                bool(ciphertext_hashes)
                and len(set(ciphertext_hashes)) == 1
            ),
            "unique_plaintext_count": len(set(plaintext_hashes)),
            "plaintext_stable": (
                bool(plaintext_hashes)
                and len(set(plaintext_hashes)) == 1
            ),
        },
        "samples": samples,
        "note": (
            "Only SHA-256 fingerprints of AES key+IV/ciphertext/plaintext are stored. "
            "No AES key, IV, SSID, owner value, or decrypted device_id is persisted."
        ),
    }
