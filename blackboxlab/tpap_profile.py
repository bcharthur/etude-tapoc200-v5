from __future__ import annotations

import base64
import hashlib
import os

from .http443_fast import post_json


ADMIN_MD5 = hashlib.md5(b"admin").hexdigest()


def _payload() -> dict:
    return {
        "method": "login",
        "params": {
            "sub_method": "pake_register",
            "username": ADMIN_MD5,
            "user_random": base64.b64encode(os.urandom(32)).decode("ascii"),
            "cipher_suites": [1],
            "encryption": ["aes_128_ccm"],
            "passcode_type": "userpw",
            "stok": None,
        },
    }


def _b64_len(value):
    if not isinstance(value, str):
        return None
    try:
        return len(base64.b64decode(value))
    except Exception:
        return None


def tpap_register_profile(
    target_ip: str,
    *,
    count: int = 6,
    timeout: float = 3.0,
) -> dict:
    samples = []

    for _ in range(count):
        raw = post_json(target_ip, "/", _payload(), timeout=timeout)
        obj = raw.get("json")
        result = (
            obj.get("result", {})
            if isinstance(obj, dict) and isinstance(obj.get("result"), dict)
            else {}
        )

        samples.append({
            "status_line": raw.get("status_line"),
            "error_code": obj.get("error_code") if isinstance(obj, dict) else None,
            "elapsed_ms": raw.get("elapsed_ms"),
            "cipher_suites": result.get("cipher_suites"),
            "iterations": result.get("iterations"),
            "encryption": result.get("encryption"),
            "dev_salt": result.get("dev_salt"),
            "dev_salt_len": _b64_len(result.get("dev_salt")),
            "dev_random": result.get("dev_random"),
            "dev_random_len": _b64_len(result.get("dev_random")),
            "dev_share": result.get("dev_share"),
            "dev_share_len": _b64_len(result.get("dev_share")),
        })

    def vals(key):
        return [s[key] for s in samples if s.get(key) is not None]

    salts = vals("dev_salt")
    randoms = vals("dev_random")
    shares = vals("dev_share")
    iterations = vals("iterations")
    ciphers = vals("cipher_suites")
    encryptions = vals("encryption")

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "password_used": False,
        "pake_share_sent": False,
        "identity": {
            "cleartext_protocol_identity": "admin",
            "md5": ADMIN_MD5,
            "note": (
                "This is treated as a TPAP protocol identity for pake:[2], "
                "not as the RTSP/ONVIF Camera Account username."
            ),
        },
        "sample_count": len(samples),
        "analysis": {
            "all_error_code_zero": bool(samples) and all(s["error_code"] == 0 for s in samples),
            "dev_salt_stable": bool(salts) and len(set(salts)) == 1,
            "unique_dev_random_count": len(set(randoms)),
            "dev_random_all_unique": bool(randoms) and len(set(randoms)) == len(randoms),
            "unique_dev_share_count": len(set(shares)),
            "dev_share_all_unique": bool(shares) and len(set(shares)) == len(shares),
            "iterations_values": sorted(set(iterations)),
            "cipher_suite_values": sorted(set(ciphers)),
            "encryption_values": sorted(set(encryptions)),
        },
        "samples": samples,
    }
