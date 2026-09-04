from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from ecdsa import NIST256p, ellipticcurve
except ImportError as exc:
    raise RuntimeError(
        "Missing dependency 'ecdsa'. Run: "
        "pip install -r requirements-thirdparty.txt"
    ) from exc


P256_M = bytes.fromhex(
    "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
)
P256_N = bytes.fromhex(
    "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
)

PAKE_CONTEXT = b"PAKE V1"

DEFAULT_SEED = b"GqY5o136oa4i6VprTlMW2DpVXxmfW8"
DEFAULT_SALT = b"tp-kdf-salt-default-passcode"
DEFAULT_INFO = b"tp-kdf-info-default-passcode"

AES_KEY_SALT = b"tp-kdf-salt-aes128-key"
AES_KEY_INFO = b"tp-kdf-info-aes128-key"
AES_IV_SALT = b"tp-kdf-salt-aes128-iv"
AES_IV_INFO = b"tp-kdf-info-aes128-iv"


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode()


def b64d(value: str) -> bytes:
    return base64.b64decode(value)


def md5hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def hkdf(master: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(master)


def hkdf_expand(label: str, material: bytes, length: int) -> bytes:
    return hkdf(
        material,
        salt=b"\x00" * length,
        info=label.encode(),
        length=length,
    )


def derive_default_passcode(mac: str) -> str:
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(mac_bytes) != 6:
        raise ValueError("Expected a 6-byte MAC address")

    ikm = DEFAULT_SEED + mac_bytes[3:6] + mac_bytes[0:3]
    return hkdf(
        ikm,
        salt=DEFAULT_SALT,
        info=DEFAULT_INFO,
        length=32,
    ).hex().upper()


def pbkdf2_ab(credential: bytes, salt: bytes, iterations: int):
    digest_len = 32
    integer_len = digest_len + 8
    material = hashlib.pbkdf2_hmac(
        "sha256",
        credential,
        salt,
        iterations,
        2 * integer_len,
    )
    return (
        int.from_bytes(material[:integer_len], "big"),
        int.from_bytes(material[integer_len:], "big"),
    )


def l8(value: bytes) -> bytes:
    return len(value).to_bytes(8, "little") + value


def encode_w(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    if length % 2 != 0 and raw[0] & 0x80:
        return b"\x00" + raw
    return raw


def sec1_xy(sec1: bytes):
    """
    Decode a P-256 SEC1 point in either standard representation:

      33 bytes:  0x02/0x03 || X          (compressed)
      65 bytes:  0x04      || X || Y     (uncompressed)

    Tapo's fixed SPAKE2+ M/N constants are compressed, while the tested
    C200 V5 returns dev_share as an uncompressed 65-byte SEC1 point.
    """
    curve = NIST256p.curve
    p = curve.p()

    if len(sec1) == 65 and sec1[0] == 0x04:
        x = int.from_bytes(sec1[1:33], "big")
        y = int.from_bytes(sec1[33:65], "big")

        if not curve.contains_point(x, y):
            raise ValueError(
                "Uncompressed SEC1 point is not on NIST P-256"
            )
        return x, y

    if len(sec1) == 33 and sec1[0] in (0x02, 0x03):
        x = int.from_bytes(sec1[1:], "big")
        rhs = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
        y = pow(rhs, (p + 1) // 4, p)

        if (y & 1) != (sec1[0] & 1):
            y = p - y

        if not curve.contains_point(x, y):
            raise ValueError(
                "Compressed SEC1 point is not on NIST P-256"
            )
        return x, y

    prefix = f"0x{sec1[0]:02x}" if sec1 else "<empty>"
    raise ValueError(
        "Unsupported SEC1 P-256 point encoding: "
        f"length={len(sec1)}, prefix={prefix}"
    )


def point_from_sec1(sec1: bytes):
    x, y = sec1_xy(sec1)
    return ellipticcurve.Point(
        NIST256p.curve,
        x,
        y,
        NIST256p.order,
    )


def uncompressed(point) -> bytes:
    return (
        b"\x04"
        + int(point.x()).to_bytes(32, "big")
        + int(point.y()).to_bytes(32, "big")
    )


def nonce_for(base_nonce: bytes, seq: int) -> bytes:
    return base_nonce[:-4] + struct.pack(">I", seq)


def _https_exchange(
    ip: str,
    request: bytes,
    *,
    timeout: float,
    binary: bool,
):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=None) as s:
            s.sendall(request)

            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 131072:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data.extend(chunk)

            head, sep, rest = bytes(data).partition(b"\r\n\r\n")
            if not sep:
                raise RuntimeError("Incomplete HTTP response headers")

            lines = head.decode("latin-1", errors="replace").splitlines()
            status = lines[0] if lines else None
            headers = {}

            for line in lines[1:]:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers.setdefault(key.strip().lower(), []).append(value.strip())

            content_length = None
            values = headers.get("content-length") or []
            if values:
                try:
                    content_length = int(values[-1])
                except ValueError:
                    pass

            body = bytearray(rest)

            if content_length is not None:
                while len(body) < content_length:
                    chunk = s.recv(min(16384, content_length - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                body_bytes = bytes(body[:content_length])
            else:
                while len(body) < 2 * 1024 * 1024:
                    try:
                        chunk = s.recv(16384)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    body.extend(chunk)
                body_bytes = bytes(body)

    if status and " 200 " not in status:
        raise RuntimeError(f"HTTP failure: {status}")

    if binary:
        return body_bytes

    text = body_bytes.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except Exception as exc:
        raise RuntimeError(
            f"Expected JSON; status={status}, body={text[:512]!r}"
        ) from exc


def https_post_json(ip: str, obj: dict, timeout=4.0) -> dict:
    body = json.dumps(obj, separators=(",", ":")).encode()
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Accept: application/json\r\n"
        "User-Agent: Tapo CameraClient Android\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body

    return _https_exchange(
        ip,
        request,
        timeout=timeout,
        binary=False,
    )


def https_post_binary(
    ip: str,
    path: str,
    payload: bytes,
    timeout=5.0,
) -> bytes:
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Accept: application/octet-stream\r\n"
        "User-Agent: Tapo CameraClient Android\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(payload)}\r\n\r\n"
    ).encode() + payload

    return _https_exchange(
        ip,
        request,
        timeout=timeout,
        binary=True,
    )


@dataclass
class TpapSession:
    ip: str
    mac: str
    stok: str
    seq: int
    key: bytes
    base_nonce: bytes
    cipher: str
    suite: int
    iterations: int

    def public_summary(self):
        return {
            "target_ip": self.ip,
            "mac": self.mac,
            "stok_present": bool(self.stok),
            "stok_sha256": hashlib.sha256(self.stok.encode()).hexdigest(),
            "start_seq": self.seq,
            "cipher": self.cipher,
            "cipher_suite": self.suite,
            "iterations": self.iterations,
            "key_sha256": hashlib.sha256(self.key).hexdigest(),
            "base_nonce_sha256": hashlib.sha256(self.base_nonce).hexdigest(),
        }

    def send(self, method: str, params: dict | None = None) -> dict:
        plaintext = json.dumps(
            {"method": method, "params": params or {}},
            separators=(",", ":"),
        ).encode()

        seq = self.seq
        aes = AESCCM(self.key, tag_length=16)
        ciphertext = aes.encrypt(
            nonce_for(self.base_nonce, seq),
            plaintext,
            None,
        )
        wire = struct.pack(">I", seq) + ciphertext

        raw_response = https_post_binary(
            self.ip,
            f"/stok={self.stok}/ds",
            wire,
        )

        if len(raw_response) < 20:
            raise RuntimeError(
                f"TPAP encrypted response too short: {len(raw_response)}"
            )

        response_seq = struct.unpack(">I", raw_response[:4])[0]
        try:
            response_plain = aes.decrypt(
                nonce_for(self.base_nonce, response_seq),
                raw_response[4:],
                None,
            )
        except Exception as exc:
            # Preserve only non-secret transport metadata. This is particularly
            # useful for distinguishing "wrong camera API envelope" from a
            # broken SPAKE2+/AES-CCM session.
            prefix = raw_response[:32].hex()
            raise RuntimeError(
                "TPAP response authentication failed; "
                f"type={type(exc).__name__}, "
                f"request_seq={seq}, response_seq={response_seq}, "
                f"response_len={len(raw_response)}, "
                f"response_prefix_hex={prefix}"
            ) from exc

        self.seq += 1
        return json.loads(response_plain.decode("utf-8"))


def discover(ip: str) -> dict:
    result = https_post_json(
        ip,
        {"method": "login", "params": {"sub_method": "discover"}},
    )
    if result.get("error_code") != 0:
        raise RuntimeError(f"discover failed: {result}")
    return result


def authenticate_default_userpw(ip: str, scoped_mac: str) -> TpapSession:
    discovery = discover(ip)
    dresult = discovery.get("result") or {}
    device_mac = str(dresult.get("mac") or "")
    pake = ((dresult.get("tpap") or {}).get("pake") or [])

    normalized_scope = scoped_mac.replace(":", "").replace("-", "").upper()
    normalized_device = device_mac.replace(":", "").replace("-", "").upper()

    if normalized_device != normalized_scope:
        raise RuntimeError(
            f"Discovery MAC {device_mac!r} does not match scoped MAC "
            f"{scoped_mac!r}"
        )

    if 0 not in pake:
        raise RuntimeError(
            f"Camera is not advertising TPAP pake:[0]; got pake={pake!r}"
        )

    passcode = derive_default_passcode(device_mac)
    user_random = os.urandom(32)

    register = https_post_json(
        ip,
        {
            "method": "login",
            "params": {
                "sub_method": "pake_register",
                "username": md5hex("admin"),
                "user_random": b64e(user_random),
                "cipher_suites": [1],
                "encryption": ["aes_128_ccm"],
                "passcode_type": "default_userpw",
                "stok": None,
            },
        },
    )

    if register.get("error_code") != 0:
        raise RuntimeError(f"pake_register failed: {register}")

    r = register.get("result") or {}
    suite = int(r.get("cipher_suites") or 1)
    encryption = str(
        r.get("encryption") or "aes_128_ccm"
    ).lower().replace("-", "_")
    iterations = int(r.get("iterations") or 5000)

    if suite != 1:
        raise RuntimeError(
            f"Expected cipher_suite 1 in this bounded client; got {suite}"
        )
    if encryption != "aes_128_ccm":
        raise RuntimeError(
            f"Expected aes_128_ccm in this bounded client; got {encryption}"
        )

    a, b = pbkdf2_ab(
        passcode.encode(),
        b64d(r["dev_salt"]),
        iterations,
    )

    G = NIST256p.generator
    order = G.order()
    M = point_from_sec1(P256_M)
    N = point_from_sec1(P256_N)
    R = point_from_sec1(b64d(r["dev_share"]))

    w = a % order
    h = b % order
    x = secrets.randbelow(order - 1) + 1

    L = x * G + w * M
    R_prime = R + (-(w * N))
    Z = x * R_prime
    V = (h % order) * R_prime

    L_enc = uncompressed(L)
    R_enc = uncompressed(R)

    context = hashlib.sha256(
        PAKE_CONTEXT + user_random + b64d(r["dev_random"])
    ).digest()

    transcript = (
        l8(context)
        + l8(b"")
        + l8(b"")
        + l8(uncompressed(M))
        + l8(uncompressed(N))
        + l8(L_enc)
        + l8(R_enc)
        + l8(uncompressed(Z))
        + l8(uncompressed(V))
        + l8(encode_w(w))
    )
    T = hashlib.sha256(transcript).digest()

    confirmation = hkdf_expand(
        "ConfirmationKeys",
        T,
        64,
    )
    kc_a = confirmation[:32]
    kc_b = confirmation[32:]

    shared = hkdf_expand(
        "SharedKey",
        T,
        32,
    )

    user_confirm = hmac.new(
        kc_a,
        R_enc,
        hashlib.sha256,
    ).digest()

    expected_dev_confirm = hmac.new(
        kc_b,
        L_enc,
        hashlib.sha256,
    ).digest()

    share = https_post_json(
        ip,
        {
            "method": "login",
            "params": {
                "sub_method": "pake_share",
                "user_share": b64e(L_enc),
                "user_confirm": b64e(user_confirm),
            },
        },
    )

    if share.get("error_code") != 0:
        raise RuntimeError(f"pake_share failed: {share}")

    s = share.get("result") or {}
    got_confirm = b64d(s.get("dev_confirm") or "")

    if not hmac.compare_digest(
        got_confirm,
        expected_dev_confirm,
    ):
        raise RuntimeError("SPAKE2+ dev_confirm mismatch")

    stok = str(s.get("sessionId") or s.get("stok") or "")
    start_seq = int(s.get("start_seq") or 1)

    if not stok:
        raise RuntimeError(
            f"pake_share returned no session token: {s}"
        )

    key = hkdf(
        shared,
        salt=AES_KEY_SALT,
        info=AES_KEY_INFO,
        length=16,
    )
    base_nonce = hkdf(
        shared,
        salt=AES_IV_SALT,
        info=AES_IV_INFO,
        length=12,
    )

    return TpapSession(
        ip=ip,
        mac=device_mac,
        stok=stok,
        seq=start_seq,
        key=key,
        base_nonce=base_nonce,
        cipher=encryption,
        suite=suite,
        iterations=iterations,
    )
