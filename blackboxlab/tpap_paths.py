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


def tpap_path_matrix(target_ip: str, timeout: float = 3.0) -> dict:
    paths = [
        "/",
        "/app",
        "/stream",
        "/does-not-exist",
    ]

    results = []

    for path in paths:
        raw = post_json(target_ip, path, _payload(), timeout=timeout)
        obj = raw.get("json")
        result_obj = (
            obj.get("result", {})
            if isinstance(obj, dict) and isinstance(obj.get("result"), dict)
            else {}
        )

        results.append({
            "path": path,
            "status_line": raw.get("status_line"),
            "error_code": obj.get("error_code") if isinstance(obj, dict) else None,
            "elapsed_ms": raw.get("elapsed_ms"),
            "sub_method": result_obj.get("sub_method"),
            "result_keys": sorted(result_obj.keys()),
            "cipher_suites": result_obj.get("cipher_suites"),
            "iterations": result_obj.get("iterations"),
            "encryption": result_obj.get("encryption"),
            "register_material_present": all(
                bool(result_obj.get(k))
                for k in ("dev_salt", "dev_random", "dev_share")
            ),
        })

    signatures = {
        (
            r["status_line"],
            r["error_code"],
            tuple(r["result_keys"]),
            r["cipher_suites"],
            r["iterations"],
            r["encryption"],
            r["register_material_present"],
        )
        for r in results
    }

    return {
        "target_ip": target_ip,
        "credentials_used": False,
        "password_used": False,
        "pake_share_sent": False,
        "results": results,
        "all_paths_same_semantic_signature": len(signatures) == 1,
        "nonexistent_http_path_accepted": any(
            r["path"] == "/does-not-exist"
            and r["error_code"] == 0
            and r["register_material_present"]
            for r in results
        ),
        "interpretation": (
            "Success on arbitrary HTTP paths suggests a catch-all JSON dispatcher; "
            "it is not an authentication bypass because pake_register is itself pre-auth."
        ),
    }
