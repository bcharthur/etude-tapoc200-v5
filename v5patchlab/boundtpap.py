from __future__ import annotations

import getpass
import hashlib
import hmac
import os
import secrets

from .boundcrypto import resolve_credential, select_candidate
from .camera_scope import load_scope, norm_mac




class BoundAuthError(RuntimeError):
    def __init__(self, message: str, *, stage: str, response: dict | None = None):
        super().__init__(message)
        self.stage = stage
        self.response = response or {}


def _safe_auth_response(obj):
    """Keep only authentication status/counter fields.

    Never emit PAKE shares, confirmations, salts, session tokens or secrets.
    """
    allowed = {
        "error_code",
        "code",
        "time",
        "max_time",
        "sec_left",
        "retry_after",
        "attempts",
        "remaining",
        "lock_time",
        "locked",
    }

    def walk(v):
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                lk = str(k).lower()
                if lk in allowed:
                    if isinstance(x, (str, int, float, bool)) or x is None:
                        out[str(k)] = x
                elif isinstance(x, (dict, list)):
                    nested = walk(x)
                    if nested not in ({}, []):
                        out[str(k)] = nested
            return out
        if isinstance(v, list):
            rows = [walk(x) for x in v]
            return [x for x in rows if x not in ({}, [])]
        return None

    return walk(obj) or {}


def auth_failure_diagnostic(exc: BoundAuthError) -> dict:
    safe = _safe_auth_response(exc.response)

    flat = {}
    def collect(v):
        if isinstance(v, dict):
            for k, x in v.items():
                lk = str(k).lower()
                if lk in {
                    "error_code", "code", "time", "max_time",
                    "sec_left", "retry_after", "attempts",
                    "remaining", "lock_time", "locked",
                } and not isinstance(x, (dict, list)):
                    flat.setdefault(lk, x)
                collect(x)
        elif isinstance(v, list):
            for x in v:
                collect(x)
    collect(safe)

    sec_left = flat.get("sec_left")
    retry_after = flat.get("retry_after")
    code = flat.get("code")
    locked = bool(flat.get("locked"))

    lockout = locked
    for value in (sec_left, retry_after):
        try:
            if value is not None and float(value) > 0:
                lockout = True
        except (TypeError, ValueError):
            pass

    # -40404 is seen publicly in Tapo authentication responses associated
    # with a temporary lockout/cooldown.
    if code == -40404:
        lockout = True

    return {
        "stage": exc.stage,
        "message": str(exc),
        "server_status": safe,
        "flattened_status": flat,
        "temporary_lockout_indicated": lockout,
        "password_logged": False,
        "credential_logged": False,
    }


def _deps():
    from ecdsa import NIST256p
    from . import tpap0
    return NIST256p, tpap0


def _discover_bound(ip: str):
    _, tp = _deps()
    d = tp.discover(ip)
    result = d.get("result") or {}
    pake = ((result.get("tpap") or {}).get("pake") or [])
    return d, result, pake


def _validate_scope(ip: str):
    scope = load_scope()
    d, result, pake = _discover_bound(ip)
    got = norm_mac(str(result.get("mac") or ""))
    expected = norm_mac(scope["target_mac"])

    if got != expected:
        raise RuntimeError(
            f"Discovery MAC {got!r} != scoped MAC {expected!r}"
        )
    if 2 not in pake:
        raise RuntimeError(
            f"Expected bound TPAP pake:[2]; got {pake!r}"
        )
    return scope, d, result


def _register(ip: str, *, user_random: bytes | None = None):
    _, tp = _deps()
    scope, discovery, dresult = _validate_scope(ip)
    user_random = user_random or os.urandom(32)

    user_hash_type = int(dresult.get("user_hash_type") or 0)
    if user_hash_type == 1:
        auth_username = hashlib.sha256(
            b"admin"
        ).hexdigest().upper()
        hash_name = "sha256-upper"
    else:
        auth_username = tp.md5hex("admin")
        hash_name = "md5-lower"

    response = tp.https_post_json(
        ip,
        {
            "method": "login",
            "params": {
                "sub_method": "pake_register",
                "username": auth_username,
                "user_random": tp.b64e(user_random),
                "cipher_suites": [1],
                "encryption": ["aes_128_ccm"],
                "passcode_type": "userpw",
                "stok": None,
            },
        },
    )

    if response.get("error_code") != 0:
        raise BoundAuthError(
            f"pake_register failed: error_code={response.get('error_code')}",
            stage="pake_register",
            response=response,
        )

    return {
        "scope": scope,
        "discovery": discovery,
        "device_mac": str(dresult.get("mac") or ""),
        "pake": ((dresult.get("tpap") or {}).get("pake") or []),
        "user_hash_type": user_hash_type,
        "auth_username_hash": hash_name,
        "user_random": user_random,
        "register_result": response.get("result") or {},
    }


def register_profile(ip: str) -> dict:
    _, tp = _deps()
    ctx = _register(ip)
    r = ctx["register_result"]
    extra = r.get("extra_crypt")

    safe_extra = None
    if isinstance(extra, dict):
        safe_extra = {
            "type": extra.get("type"),
            "params": extra.get("params"),
        }

    return {
        "target_ip": ip,
        "discovery": ctx["discovery"],
        "pake": ctx["pake"],
        "passcode_type": "userpw",
        "user_hash_type": ctx["user_hash_type"],
        "auth_username": "admin (hashed on wire)",
        "auth_username_hash": ctx["auth_username_hash"],
        "cipher_suite": int(r.get("cipher_suites") or 1),
        "encryption": str(r.get("encryption") or "aes_128_ccm"),
        "iterations": int(r.get("iterations") or 0),
        "dev_salt_len": len(tp.b64d(r.get("dev_salt") or "")),
        "dev_random_len": len(tp.b64d(r.get("dev_random") or "")),
        "dev_share_len": len(tp.b64d(r.get("dev_share") or "")),
        "extra_crypt": safe_extra,
        "note": (
            "pake_register only. No password supplied, no pake_share, "
            "and no management request."
        ),
    }


def authenticate_bound(ip: str, *, password: str, candidate: str = "raw"):
    NIST256p, tp = _deps()

    ctx = _register(ip)
    r = ctx["register_result"]
    mac = ctx["device_mac"]

    suite = int(r.get("cipher_suites") or 1)
    encryption = str(
        r.get("encryption") or "aes_128_ccm"
    ).lower().replace("-", "_")
    iterations = int(r.get("iterations") or 5000)

    if suite != 1:
        raise RuntimeError(f"Expected suite 1; negotiated {suite}")
    if encryption != "aes_128_ccm":
        raise RuntimeError(
            f"Expected aes_128_ccm; negotiated {encryption}"
        )

    selected = select_candidate(password, candidate)
    credential, transform = resolve_credential(
        selected,
        mac=mac,
        extra_crypt=r.get("extra_crypt"),
        smartcam=True,
    )

    a, b = tp.pbkdf2_ab(
        credential.encode(),
        tp.b64d(r["dev_salt"]),
        iterations,
    )

    G = NIST256p.generator
    order = G.order()
    M = tp.point_from_sec1(tp.P256_M)
    N = tp.point_from_sec1(tp.P256_N)
    R = tp.point_from_sec1(tp.b64d(r["dev_share"]))

    w = a % order
    h = b % order
    x = secrets.randbelow(order - 1) + 1

    L = x * G + w * M
    R_prime = R + (-(w * N))
    Z = x * R_prime
    V = (h % order) * R_prime

    L_enc = tp.uncompressed(L)
    R_enc = tp.uncompressed(R)

    context = hashlib.sha256(
        tp.PAKE_CONTEXT
        + ctx["user_random"]
        + tp.b64d(r["dev_random"])
    ).digest()

    transcript = (
        tp.l8(context)
        + tp.l8(b"")
        + tp.l8(b"")
        + tp.l8(tp.uncompressed(M))
        + tp.l8(tp.uncompressed(N))
        + tp.l8(L_enc)
        + tp.l8(R_enc)
        + tp.l8(tp.uncompressed(Z))
        + tp.l8(tp.uncompressed(V))
        + tp.l8(tp.encode_w(w))
    )
    T = hashlib.sha256(transcript).digest()

    confirmation = tp.hkdf_expand("ConfirmationKeys", T, 64)
    kc_a = confirmation[:32]
    kc_b = confirmation[32:]
    shared = tp.hkdf_expand("SharedKey", T, 32)

    user_confirm = hmac.new(
        kc_a, R_enc, hashlib.sha256
    ).digest()
    expected_dev_confirm = hmac.new(
        kc_b, L_enc, hashlib.sha256
    ).digest()

    share = tp.https_post_json(
        ip,
        {
            "method": "login",
            "params": {
                "sub_method": "pake_share",
                "user_share": tp.b64e(L_enc),
                "user_confirm": tp.b64e(user_confirm),
            },
        },
    )

    if share.get("error_code") != 0:
        raise BoundAuthError(
            f"pake_share failed: error_code={share.get('error_code')}",
            stage="pake_share",
            response=share,
        )

    s = share.get("result") or {}
    got_confirm = tp.b64d(s.get("dev_confirm") or "")
    if not hmac.compare_digest(got_confirm, expected_dev_confirm):
        raise RuntimeError("SPAKE2+ dev_confirm mismatch")

    stok = str(s.get("sessionId") or s.get("stok") or "")
    if not stok:
        raise RuntimeError("pake_share returned no session token")

    start_seq = int(s.get("start_seq") or 1)
    key = tp.hkdf(
        shared,
        salt=tp.AES_KEY_SALT,
        info=tp.AES_KEY_INFO,
        length=16,
    )
    base_nonce = tp.hkdf(
        shared,
        salt=tp.AES_IV_SALT,
        info=tp.AES_IV_INFO,
        length=12,
    )

    session = tp.TpapSession(
        ip=ip,
        mac=mac,
        stok=stok,
        seq=start_seq,
        key=key,
        base_nonce=base_nonce,
        cipher=encryption,
        suite=suite,
        iterations=iterations,
    )

    return session, {
        "candidate": candidate,
        "candidate_value_logged": False,
        "credential_value_logged": False,
        "credential_transform": transform,
        "passcode_type": "userpw",
        "auth_username": "admin (hashed on wire)",
        "user_hash_type": ctx["user_hash_type"],
    }


def prompt_bound_password(label: str) -> str:
    value = getpass.getpass(f"{label}: ")
    if not value:
        raise RuntimeError("Empty password refused")
    return value
