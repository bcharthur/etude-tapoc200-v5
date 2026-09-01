from __future__ import annotations

import lzma
import re
import struct
from pathlib import Path


UIMAGE_MAGIC = 0x27051956
COMP_NAMES = {
    0: "none",
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}


def parse_uimage(data: bytes) -> dict:
    if len(data) < 64:
        raise ValueError("File too short for legacy U-Boot uImage")

    (
        magic, hcrc, timestamp, size, load, entry, dcrc,
        os_id, arch, image_type, comp,
    ) = struct.unpack(">7I4B", data[:32])

    if magic != UIMAGE_MAGIC:
        raise ValueError(f"Not a legacy uImage: magic=0x{magic:08x}")

    name = data[32:64].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    payload = data[64:64 + size]

    return {
        "magic": magic,
        "header_crc": hcrc,
        "timestamp": timestamp,
        "payload_size": size,
        "load_address": load,
        "entry_point": entry,
        "data_crc": dcrc,
        "os": os_id,
        "arch": arch,
        "type": image_type,
        "compression": comp,
        "compression_name": COMP_NAMES.get(comp, f"unknown:{comp}"),
        "name": name,
        "payload": payload,
    }


def decompress_payload(info: dict) -> bytes:
    payload = info["payload"]
    comp = info["compression"]

    if comp == 0:
        return payload
    if comp == 3:
        attempts = [
            lambda: lzma.decompress(payload),
            lambda: lzma.decompress(payload, format=lzma.FORMAT_ALONE),
            lambda: lzma.decompress(payload, format=lzma.FORMAT_AUTO),
        ]
        last = None
        for fn in attempts:
            try:
                return fn()
            except Exception as exc:
                last = exc
        raise RuntimeError(f"Could not decompress uImage LZMA payload: {last}")

    raise RuntimeError(
        f"Compression {info['compression_name']} is not implemented by rootlab"
    )


def find_tp_link_keys(kernel_bytes: bytes) -> list[dict]:
    hits = []
    start = 0
    while True:
        pos = kernel_bytes.find(b"TP_LINK", start)
        if pos < 0:
            break
        candidate = kernel_bytes[pos:pos + 16]
        if len(candidate) == 16 and all(32 <= b <= 126 for b in candidate):
            hits.append({
                "offset": pos,
                "ascii": candidate.decode("ascii"),
                "hex": candidate.hex(),
            })
        start = pos + 1
    return hits


def inspect_kernel(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    info = parse_uimage(data)
    plain = decompress_payload(info)
    keys = find_tp_link_keys(plain)
    out = {k: v for k, v in info.items() if k != "payload"}
    out["decompressed_size"] = len(plain)
    out["rootfs_key_candidates"] = keys
    return out
