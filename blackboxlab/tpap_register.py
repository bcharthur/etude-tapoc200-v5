from __future__ import annotations

import base64
import hashlib
import os

from .http443_fast import post_json


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _register_payload(username_hash: str) -> dict:
    return {
        "method": "login",
        "params": {
            "sub_method": "pake_register",
            "username": username_hash,
            "user_random": base64.b64encode(os.urandom(32)).decode("ascii"),
            "cipher_suites": [1],
            "encryption": ["aes_128_ccm"],
            "passcode_type": "userpw",
            "stok": None,
        },
    }


def _summarize(result: dict) -> dict:
    obj = result.get("json")
    error_code = obj.get("error_code") if isinstance(obj, dict) else None
    reg = obj.get("result") if isinstance(obj, dict) and isinstance(obj.get("result"), dict) else {}

    # Keep protocol parameters, but don't pretend any of them are credentials.
    return {
        "status_line": result.get("status_line"),
        "error_code": error_code,
        "elapsed_ms": result.get("elapsed_ms"),
        "result_keys": sorted(reg.keys()),
        "cipher_suites": reg.get("cipher_suites"),
        "encryption": reg.get("encryption"),
        "iterations": reg.get("iterations"),
        "extra_crypt": reg.get("extra_crypt"),
        "dev_salt_present": bool(reg.get("dev_salt")),
        "dev_share_present": bool(reg.get("dev_share")),
        "dev_random_present": bool(reg.get("dev_random")),
    }


def tpap_register_probe(target_ip: str, timeout: float = 3.0) -> dict:
    """
    Stop at SPAKE2+ step 1. No password and no pake_share.

    Two requests only:
      - conventionally hashed 'admin'
      - one fixed nonexistent label

    This is intended to detect whether register behavior itself exposes a
    username-existence oracle. It is not enumeration or guessing.
    """
    identities = {
        "admin_md5": _md5_hex("admin"),
        "nonexistent_md5": _md5_hex("tapolab-blackbox-definitely-nonexistent"),
    }

    results = {}

    for label, username_hash in identities.items():
        raw = post_json(
            target_ip,
            "/",
            _register_payload(username_hash),
            timeout=timeout,
        )
        results[label] = {
            "username_hash": username_hash,
            "summary": _summarize(raw),
            "raw": raw,
        }

    a = results["admin_md5"]["summary"]
    b = results["nonexistent_md5"]["summary"]

    oracle_difference = any(
        a.get(key) != b.get(key)
        for key in (
            "error_code",
            "result_keys",
            "cipher_suites",
            "encryption",
            "iterations",
            "extra_crypt",
            "dev_salt_present",
            "dev_share_present",
            "dev_random_present",
        )
    )

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "password_used": False,
        "pake_share_sent": False,
        "session_created": False,
        "tests": results,
        "possible_username_oracle": oracle_difference,
        "interpretation": (
            "A difference is only a candidate username-existence oracle; "
            "it is not an authentication bypass."
        ),
    }
