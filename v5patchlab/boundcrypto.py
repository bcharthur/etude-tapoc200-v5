from __future__ import annotations

import base64
import hashlib


def _norm_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


def _md5_lower(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def _sha256_upper(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest().upper()


def _to64(value: int, n: int) -> str:
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    out = []
    for _ in range(n):
        out.append(alphabet[value & 0x3F])
        value >>= 6
    return "".join(out)


def md5_crypt(password: str, prefix: str) -> str:
    parts = [x for x in prefix.split("$") if x]
    if len(parts) < 2 or parts[0] != "1":
        raise ValueError(f"Unsupported MD5-crypt prefix: {prefix!r}")
    salt = parts[1][:8]
    pw = password.encode()
    sl = salt.encode()

    alt = hashlib.md5(pw + sl + pw).digest()
    ctx = hashlib.md5()
    ctx.update(pw)
    ctx.update(b"$1$")
    ctx.update(sl)

    remain = len(pw)
    while remain > 0:
        ctx.update(alt[: min(remain, 16)])
        remain -= 16

    i = len(pw)
    while i > 0:
        ctx.update(b"\x00" if (i & 1) else pw[:1])
        i >>= 1

    result = ctx.digest()

    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if (i & 1) else result)
        if i % 3:
            c.update(sl)
        if i % 7:
            c.update(pw)
        c.update(result if (i & 1) else pw)
        result = c.digest()

    encoded = ""
    encoded += _to64((result[0] << 16) | (result[6] << 8) | result[12], 4)
    encoded += _to64((result[1] << 16) | (result[7] << 8) | result[13], 4)
    encoded += _to64((result[2] << 16) | (result[8] << 8) | result[14], 4)
    encoded += _to64((result[3] << 16) | (result[9] << 8) | result[15], 4)
    encoded += _to64((result[4] << 16) | (result[10] << 8) | result[5], 4)
    encoded += _to64(result[11], 2)
    return f"$1${salt}${encoded}"


def sha256_crypt(password: str, prefix: str, rounds: int | None = None) -> str:
    parts = [x for x in prefix.split("$") if x]
    if len(parts) < 2 or parts[0] != "5":
        raise ValueError(f"Unsupported SHA256-crypt prefix: {prefix!r}")

    parsed_rounds = rounds
    if parts[1].startswith("rounds="):
        if parsed_rounds is None:
            parsed_rounds = int(parts[1].split("=", 1)[1])
        salt = parts[2][:16]
        rounds_explicit = True
    else:
        salt = parts[1][:16]
        rounds_explicit = rounds is not None

    r = int(parsed_rounds or 5000)
    r = min(max(r, 1000), 999_999_999)

    pw = password.encode()
    sl = salt.encode()

    b_digest = hashlib.sha256(pw + sl + pw).digest()

    a = hashlib.sha256()
    a.update(pw)
    a.update(sl)

    remain = len(pw)
    while remain > 0:
        a.update(b_digest[: min(remain, 32)])
        remain -= 32

    i = len(pw)
    while i > 0:
        a.update(b_digest if (i & 1) else pw)
        i >>= 1
    result = a.digest()

    dp_ctx = hashlib.sha256()
    for _ in range(len(pw)):
        dp_ctx.update(pw)
    dp = dp_ctx.digest()
    p_seq = (dp * ((len(pw) + 31) // 32))[:len(pw)]

    ds_ctx = hashlib.sha256()
    for _ in range(16 + result[0]):
        ds_ctx.update(sl)
    ds = ds_ctx.digest()
    s_seq = (ds * ((len(sl) + 31) // 32))[:len(sl)]

    for i in range(r):
        c = hashlib.sha256()
        c.update(p_seq if (i & 1) else result)
        if i % 3:
            c.update(s_seq)
        if i % 7:
            c.update(p_seq)
        c.update(result if (i & 1) else p_seq)
        result = c.digest()

    encoded = ""
    encoded += _to64((result[0] << 16) | (result[10] << 8) | result[20], 4)
    encoded += _to64((result[21] << 16) | (result[1] << 8) | result[11], 4)
    encoded += _to64((result[12] << 16) | (result[22] << 8) | result[2], 4)
    encoded += _to64((result[3] << 16) | (result[13] << 8) | result[23], 4)
    encoded += _to64((result[24] << 16) | (result[4] << 8) | result[14], 4)
    encoded += _to64((result[15] << 16) | (result[25] << 8) | result[5], 4)
    encoded += _to64((result[6] << 16) | (result[16] << 8) | result[26], 4)
    encoded += _to64((result[27] << 16) | (result[7] << 8) | result[17], 4)
    encoded += _to64((result[18] << 16) | (result[28] << 8) | result[8], 4)
    encoded += _to64((result[9] << 16) | (result[19] << 8) | result[29], 4)
    encoded += _to64((result[31] << 8) | result[30], 3)

    rounds_part = f"rounds={r}$" if rounds_explicit else ""
    return f"$5${rounds_part}{salt}${encoded}"


def select_candidate(password: str, candidate: str) -> str:
    if candidate == "raw":
        return password
    if candidate == "md5":
        return _md5_lower(password)
    if candidate == "sha256":
        return _sha256_upper(password)
    raise ValueError("candidate must be raw, md5, or sha256")


def resolve_credential(
    candidate_secret: str,
    *,
    mac: str,
    extra_crypt,
    smartcam: bool = True,
) -> tuple[str, dict]:
    if not extra_crypt:
        return candidate_secret, {
            "extra_crypt": None,
            "transform": "identity-smartcam" if smartcam else "identity",
        }

    crypt_type = str(extra_crypt.get("type") or "").lower()
    params = extra_crypt.get("params") or {}

    if crypt_type == "password_shadow":
        passwd_id = int(params.get("passwd_id") or 0)
        prefix = str(params.get("passwd_prefix") or "")

        if passwd_id == 1:
            value = md5_crypt(candidate_secret, prefix)
            transform = "md5_crypt"
        elif passwd_id == 2:
            value = hashlib.sha1(candidate_secret.encode()).hexdigest()
            transform = "sha1"
        elif passwd_id == 3:
            mac_clean = _norm_mac(mac)
            mac_colon = ":".join(
                mac_clean[i:i+2] for i in range(0, 12, 2)
            )
            md5pw = _md5_lower(candidate_secret)
            value = hashlib.sha1(
                f"{md5pw}_{mac_colon}".encode()
            ).hexdigest()
            transform = "sha1(md5(password)_MAC)"
        elif passwd_id == 5:
            pr = params.get("passwd_rounds")
            value = sha256_crypt(
                candidate_secret,
                prefix,
                int(pr) if pr else None,
            )
            transform = "sha256_crypt"
        else:
            raise RuntimeError(
                f"Unsupported password_shadow passwd_id={passwd_id}"
            )

        return value, {
            "extra_crypt": "password_shadow",
            "passwd_id": passwd_id,
            "transform": transform,
            "credential_length": len(value),
        }

    if crypt_type == "password_authkey":
        tmpkey = str(params.get("authkey_tmpkey") or "")
        dictionary = str(params.get("authkey_dictionary") or "")
        if not tmpkey or not dictionary:
            raise RuntimeError(
                "password_authkey missing authkey_tmpkey/dictionary"
            )
        max_len = max(len(tmpkey), len(candidate_secret))
        chars = []
        for i in range(max_len):
            a = ord(candidate_secret[i]) if i < len(candidate_secret) else 0xBB
            b = ord(tmpkey[i]) if i < len(tmpkey) else 0xBB
            chars.append(dictionary[(a ^ b) % len(dictionary)])
        value = "".join(chars)
        return value, {
            "extra_crypt": "password_authkey",
            "transform": "xor-dictionary",
            "credential_length": len(value),
        }

    if crypt_type == "password_sha_with_salt":
        sha_name = int(params.get("sha_name") or 0)
        name = b"admin" if sha_name == 0 else b"user"
        salt = base64.b64decode(str(params.get("sha_salt") or ""))
        value = hashlib.sha256(
            name + salt + candidate_secret.encode()
        ).hexdigest()
        return value, {
            "extra_crypt": "password_sha_with_salt",
            "sha_name": sha_name,
            "transform": "sha256(name+salt+password)",
            "credential_length": len(value),
        }

    raise RuntimeError(
        f"Unsupported TPAP extra_crypt type: {crypt_type!r}"
    )
