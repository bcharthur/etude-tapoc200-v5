from __future__ import annotations

import shutil
from pathlib import Path

from .crypto import aes_cfb1
from .evidence import sha256_file, write_json
from .layout import FLASH_SIZE, PARTITIONS, ROOTFS_START, ROOTFS_END, ROOTFS_SIZE, ROOTFS_IV
from .uimage import parse_uimage, decompress_payload, find_tp_link_keys


def validate_dump(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)

    size = p.stat().st_size
    return {
        "path": str(p),
        "size": size,
        "expected_size": FLASH_SIZE,
        "size_ok": size == FLASH_SIZE,
        "sha256": sha256_file(p),
    }


def carve(path: str | Path, out_dir: str | Path) -> dict:
    src = Path(path)
    validation = validate_dump(src)
    if not validation["size_ok"]:
        raise RuntimeError(
            f"Expected exact 8 MiB dump (0x{FLASH_SIZE:x}), got {validation['size']}"
        )

    data = src.read_bytes()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    parts = []
    for name, (start, end) in PARTITIONS.items():
        target = out / f"{name}.bin"
        target.write_bytes(data[start:end])
        parts.append({
            "name": name,
            "start": start,
            "end": end,
            "size": end - start,
            "path": str(target),
            "sha256": sha256_file(target),
        })

    result = {
        "dump": validation,
        "partitions": parts,
    }
    write_json(out / "manifest.json", result)
    return result


def _auto_rootfs_key(dump: bytes) -> bytes:
    ks, ke = PARTITIONS["kernel"]
    kernel = dump[ks:ke]
    info = parse_uimage(kernel)
    plain = decompress_payload(info)
    hits = find_tp_link_keys(plain)

    if len(hits) != 1:
        raise RuntimeError(
            "Could not uniquely derive rootfs AES key from decompressed kernel: "
            f"{len(hits)} TP_LINK candidates. Use --key-ascii or --key-hex."
        )
    return bytes.fromhex(hits[0]["hex"])


def resolve_key(
    dump: bytes,
    *,
    key_ascii: str | None = None,
    key_hex: str | None = None,
) -> tuple[bytes, str]:
    if key_ascii and key_hex:
        raise ValueError("Use only one of --key-ascii / --key-hex")
    if key_ascii:
        key = key_ascii.encode()
        source = "explicit-ascii"
    elif key_hex:
        key = bytes.fromhex(key_hex)
        source = "explicit-hex"
    else:
        key = _auto_rootfs_key(dump)
        source = "kernel-auto"

    if len(key) != 16:
        raise ValueError(f"Rootfs AES key must be 16 bytes, got {len(key)}")
    return key, source


def decrypt_rootfs(
    dump_path: str | Path,
    out_path: str | Path,
    *,
    key_ascii: str | None = None,
    key_hex: str | None = None,
) -> dict:
    dump_p = Path(dump_path)
    data = dump_p.read_bytes()
    if len(data) != FLASH_SIZE:
        raise RuntimeError("Expected exact 8 MiB dump")

    key, source = resolve_key(data, key_ascii=key_ascii, key_hex=key_hex)
    rootfs = bytearray(data[ROOTFS_START:ROOTFS_END])
    rootfs[:512] = aes_cfb1(rootfs[:512], key, ROOTFS_IV, decrypt=True)

    magic_ok = bytes(rootfs[:4]) == b"hsqs"
    if not magic_ok:
        raise RuntimeError(
            "Decrypted rootfs does not start with SquashFS magic 'hsqs'. "
            "Do not continue; key/firmware layout mismatch."
        )

    out_p = Path(out_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_bytes(rootfs)

    return {
        "dump": str(dump_p),
        "output": str(out_p),
        "output_sha256": sha256_file(out_p),
        "rootfs_size": len(rootfs),
        "squashfs_magic_ok": True,
        "key_source": source,
        "key_sha256": __import__("hashlib").sha256(key).hexdigest(),
    }


def build_flash_image(
    original_dump: str | Path,
    plain_rootfs: str | Path,
    output: str | Path,
    *,
    key_ascii: str | None = None,
    key_hex: str | None = None,
) -> dict:
    original = Path(original_dump)
    rootfs_p = Path(plain_rootfs)
    out = Path(output)

    base = bytearray(original.read_bytes())
    if len(base) != FLASH_SIZE:
        raise RuntimeError("Original dump is not exact 8 MiB")

    fs = bytearray(rootfs_p.read_bytes())
    if len(fs) > ROOTFS_SIZE:
        raise RuntimeError(
            f"Repacked rootfs is too large: {len(fs)} > partition {ROOTFS_SIZE}"
        )
    if fs[:4] != b"hsqs":
        raise RuntimeError("Repacked rootfs does not start with SquashFS magic")

    key, source = resolve_key(bytes(base), key_ascii=key_ascii, key_hex=key_hex)

    # Produce encrypted-on-flash rootfs without modifying the plain artifact.
    encrypted = bytearray(fs)
    first = bytes(encrypted[:512]).ljust(512, b"\x00")
    encrypted[:512] = aes_cfb1(first, key, ROOTFS_IV, decrypt=False)

    # Clear only rootfs partition in the copy, preserve everything else exactly.
    base[ROOTFS_START:ROOTFS_END] = b"\x00" * ROOTFS_SIZE
    base[ROOTFS_START:ROOTFS_START + len(encrypted)] = encrypted

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(base)

    # Verify round-trip first 512 bytes.
    verify = aes_cfb1(
        bytes(base[ROOTFS_START:ROOTFS_START + 512]),
        key,
        ROOTFS_IV,
        decrypt=True,
    )
    if verify[:4] != b"hsqs":
        raise RuntimeError("Internal CFB1 round-trip verification failed")

    return {
        "original": str(original),
        "original_sha256": sha256_file(original),
        "plain_rootfs": str(rootfs_p),
        "plain_rootfs_sha256": sha256_file(rootfs_p),
        "plain_rootfs_size": len(fs),
        "partition_capacity": ROOTFS_SIZE,
        "free_bytes": ROOTFS_SIZE - len(fs),
        "output": str(out),
        "output_size": out.stat().st_size,
        "output_sha256": sha256_file(out),
        "key_source": source,
        "roundtrip_magic_ok": True,
    }
