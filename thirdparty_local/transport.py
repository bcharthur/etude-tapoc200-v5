from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import ssl
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_ADMIN_PASSWORD = "TPL075526460603"

THIRD_ACCOUNT_PUBLIC_KEY_PEM = b'''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4D6i0oD/Ga5qb//RfSe8MrPVI
rMIGecCxkcGWGj9kxxk74qQNq8XUuXoy2PczQ30BpiRHrlkbtBEPeWLpq85tfubT
UjhBz1NPNvWrC88uaYVGvzNpgzZOqDC35961uPTuvdUa8vztcUQjEZy16WbmetRj
URFIiWJgFCmemyYVbQIDAQAB
-----END PUBLIC KEY-----
'''


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest().upper()


def token(name: str, nonce: str, cnonce: str, hashed_key: str) -> bytes:
    h = hashlib.sha256(
        f"{name}{cnonce}{nonce}{hashed_key}".encode()
    ).hexdigest()
    return bytes.fromhex(h[:32])


def aes_encrypt_b64(plaintext: bytes, key: bytes, iv: bytes) -> str:
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(ct).decode()


def aes_decrypt_b64(payload: str, key: bytes, iv: bytes) -> bytes:
    ct = base64.b64decode(payload)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def rsa_encrypt_pkcs1_b64(public_pem: bytes, value: str) -> str:
    key = serialization.load_pem_public_key(public_pem)
    ct = key.encrypt(value.encode(), asympadding.PKCS1v15())
    return base64.b64encode(ct).decode()


def _https_post(ip: str, path: str, obj: dict, headers=None, timeout=3.0):
    body = json.dumps(obj, separators=(",", ":")).encode()

    req_headers = {
        "Host": ip,
        "Content-Type": "application/json",
        "User-Agent": "Tapo CameraClient Android",
        "Connection": "close",
        "Content-Length": str(len(body)),
    }
    if headers:
        req_headers.update(headers)

    request = (
        f"POST {path} HTTP/1.1\\r\\n"
        + "".join(f"{k}: {v}\\r\\n" for k, v in req_headers.items())
        + "\\r\\n"
    ).encode() + body

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=None) as s:
            s.sendall(request)
            data = bytearray()

            while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
                c = s.recv(8192)
                if not c:
                    break
                data.extend(c)

            head, sep, rest = bytes(data).partition(b"\\r\\n\\r\\n")
            if not sep:
                raise RuntimeError("Incomplete HTTPS response")

            lines = head.decode("latin-1", errors="replace").splitlines()
            status = lines[0] if lines else None

            content_length = None
            for line in lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                if k.strip().lower() == "content-length":
                    try:
                        content_length = int(v.strip())
                    except ValueError:
                        pass

            buf = bytearray(rest)
            while content_length is not None and len(buf) < content_length:
                c = s.recv(min(8192, content_length - len(buf)))
                if not c:
                    break
                buf.extend(c)

    raw_body = bytes(buf[:content_length] if content_length is not None else buf)
    text = raw_body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None

    return {
        "status_line": status,
        "json": parsed,
        "body_preview": None if parsed is not None else text[:2048],
    }


@dataclass
class LegacySession:
    ip: str
    cnonce: str
    nonce: str
    hashed_password: str
    hashed_key: str
    lsk: bytes
    ivb: bytes
    seq: int
    stok: str


def legacy_login(ip: str, password: str = DEFAULT_ADMIN_PASSWORD) -> LegacySession:
    cnonce = secrets.token_hex(8).upper()

    phase1 = _https_post(
        ip,
        "/",
        {
            "method": "login",
            "params": {
                "cnonce": cnonce,
                "encrypt_type": "3",
                "username": "admin",
            },
        },
    )

    obj = phase1["json"]
    if not isinstance(obj, dict):
        raise RuntimeError(f"Phase1 returned no JSON: {phase1}")

    data = ((obj.get("result") or {}).get("data") or {})
    nonce = data.get("nonce")
    device_confirm = data.get("device_confirm")

    if not nonce or not device_confirm:
        raise RuntimeError(
            f"Legacy phase1 did not return nonce/device_confirm: {obj}"
        )

    hashed_password = sha256_hex(password)
    hashed_key = sha256_hex(f"{cnonce}{hashed_password}{nonce}")
    expected_confirm = f"{hashed_key}{nonce}{cnonce}"

    if expected_confirm != device_confirm:
        raise RuntimeError(
            "Default setup admin password did not validate against device_confirm."
        )

    digest_password = (
        sha256_hex(f"{hashed_password}{cnonce}{nonce}")
        + cnonce
        + nonce
    )

    phase2 = _https_post(
        ip,
        "/",
        {
            "method": "login",
            "params": {
                "cnonce": cnonce,
                "encrypt_type": "3",
                "digest_passwd": digest_password,
                "username": "admin",
            },
        },
    )

    obj2 = phase2["json"]
    if not isinstance(obj2, dict):
        raise RuntimeError(f"Phase2 returned no JSON: {phase2}")

    result = obj2.get("result") or {}
    stok = result.get("stok")
    start_seq = result.get("start_seq")

    if not stok or start_seq is None:
        raise RuntimeError(f"Legacy phase2 did not return stok/start_seq: {obj2}")

    return LegacySession(
        ip=ip,
        cnonce=cnonce,
        nonce=nonce,
        hashed_password=hashed_password,
        hashed_key=hashed_key,
        lsk=token("lsk", nonce, cnonce, hashed_key),
        ivb=token("ivb", nonce, cnonce, hashed_key),
        seq=int(start_seq),
        stok=stok,
    )


def _tapo_tag(sess: LegacySession, body_json: str, seq: int) -> str:
    tag = sha256_hex(f"{sess.hashed_password}{sess.cnonce}")
    return sha256_hex(f"{tag}{body_json}{seq}")


def secure_request(sess: LegacySession, requests: list[dict]) -> dict:
    inner = {
        "method": "multipleRequest",
        "params": {"requests": requests},
    }
    inner_raw = json.dumps(inner, separators=(",", ":")).encode()

    encrypted = aes_encrypt_b64(inner_raw, sess.lsk, sess.ivb)
    outer = {
        "method": "securePassthrough",
        "params": {"request": encrypted},
    }

    outer_raw = json.dumps(outer, separators=(",", ":"))
    seq = sess.seq
    sess.seq += 1

    response = _https_post(
        sess.ip,
        f"/stok={sess.stok}/ds",
        outer,
        headers={
            "seq": str(seq),
            "tapo_tag": _tapo_tag(sess, outer_raw, seq),
        },
    )

    obj = response["json"]
    if not isinstance(obj, dict):
        raise RuntimeError(f"securePassthrough returned no JSON: {response}")

    enc_response = ((obj.get("result") or {}).get("response"))
    if not enc_response:
        return {"outer": obj, "decrypted": None}

    plain = aes_decrypt_b64(enc_response, sess.lsk, sess.ivb)
    try:
        decoded = json.loads(plain.decode())
    except Exception:
        decoded = {"raw": plain.decode("utf-8", errors="replace")}

    return {"outer": obj, "decrypted": decoded}


def enable_third_account(
    sess: LegacySession,
    *,
    username: str,
    password: str,
) -> dict:
    hashed_new_password = md5_hex(password)
    ciphertext = rsa_encrypt_pkcs1_b64(
        THIRD_ACCOUNT_PUBLIC_KEY_PEM,
        password,
    )

    requests = [
        {
            "method": "setAccountEnabled",
            "params": {
                "user_management": {
                    "set_account_enabled": {
                        "enabled": "on",
                        "secname": "third_account",
                    }
                }
            },
        },
        {
            "method": "changeThirdAccount",
            "params": {
                "user_management": {
                    "change_third_account": {
                        "secname": "third_account",
                        "passwd": hashed_new_password,
                        "old_passwd": "",
                        "ciphertext": ciphertext,
                        "username": username,
                    }
                }
            },
        },
    ]

    return secure_request(sess, requests)
