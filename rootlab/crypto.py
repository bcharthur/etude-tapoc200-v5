from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_block_encrypt(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def aes_cfb1(data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
    """AES CFB-1, MSB-first, compatible with `openssl enc -aes-128-cfb1`.

    For both encryption and decryption the feedback bit is the ciphertext bit.
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CFB1 requires 16-byte key and IV")

    reg = int.from_bytes(iv, "big")
    mask128 = (1 << 128) - 1
    out = bytearray(len(data))

    for byte_index, src_byte in enumerate(data):
        dst = 0
        for bit_index in range(8):
            in_bit = (src_byte >> (7 - bit_index)) & 1
            stream_block = aes_block_encrypt(key, reg.to_bytes(16, "big"))
            stream_bit = (stream_block[0] >> 7) & 1
            out_bit = in_bit ^ stream_bit

            # encryption: input=plain, output=cipher
            # decryption: input=cipher, output=plain
            cipher_bit = in_bit if decrypt else out_bit

            dst |= out_bit << (7 - bit_index)
            reg = ((reg << 1) & mask128) | cipher_bit

        out[byte_index] = dst

    return bytes(out)


# Pure Python md5-crypt ($1$), used by the published Rev.5 workflow.
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_B64[value & 0x3F])
        value >>= 6
    return "".join(out)


def md5crypt(password: str, salt: str | None = None) -> str:
    if salt is None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        salt = "".join(secrets.choice(alphabet) for _ in range(8))
    salt = salt.split("$")[0][:8]

    pw = password.encode()
    sl = salt.encode()
    magic = b"$1$"

    alt = hashlib.md5(pw + sl + pw).digest()

    ctx = hashlib.md5()
    ctx.update(pw)
    ctx.update(magic)
    ctx.update(sl)

    remain = len(pw)
    while remain > 0:
        ctx.update(alt[:min(16, remain)])
        remain -= 16

    i = len(pw)
    while i > 0:
        if i & 1:
            ctx.update(b"\x00")
        else:
            ctx.update(pw[:1])
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
