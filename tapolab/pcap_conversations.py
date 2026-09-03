from __future__ import annotations

import socket
import struct
from collections import defaultdict
from pathlib import Path

from .pcap import iter_pcap_raw_ipv4


def _ipv4(packet: bytes):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None

    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None

    total = struct.unpack("!H", packet[2:4])[0]
    proto = packet[9]
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])

    return {
        "src": src,
        "dst": dst,
        "proto": proto,
        "payload": packet[ihl:total] if total else packet[ihl:],
    }


def _tcp(segment: bytes):
    if len(segment) < 20:
        return None

    src_port, dst_port = struct.unpack("!HH", segment[:4])
    seq = struct.unpack("!I", segment[4:8])[0]
    data_offset = ((segment[12] >> 4) & 0xF) * 4

    if data_offset < 20 or len(segment) < data_offset:
        return None

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "flags": segment[13],
        "payload": segment[data_offset:],
    }


def _preview(data: bytes, limit: int = 1024) -> str:
    data = data[:limit]
    out = []
    for b in data:
        if b in (9, 10, 13):
            out.append(chr(b))
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def tcp_conversations(path: Path, target_ip: str) -> dict:
    convs = {}
    seen_payloads = set()

    for record in iter_pcap_raw_ipv4(path):
        ip = _ipv4(record["packet"])
        if not ip or ip["proto"] != 6:
            continue

        tcp = _tcp(ip["payload"])
        if not tcp:
            continue

        if target_ip not in {ip["src"], ip["dst"]}:
            continue

        a = (ip["src"], tcp["src_port"])
        b = (ip["dst"], tcp["dst_port"])

        # Canonical connection key independent of direction.
        key = tuple(sorted((a, b)))
        key_s = f"{key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}"

        if key_s not in convs:
            convs[key_s] = {
                "endpoint_a": f"{key[0][0]}:{key[0][1]}",
                "endpoint_b": f"{key[1][0]}:{key[1][1]}",
                "packets": 0,
                "payload_bytes": 0,
                "camera_port": (
                    tcp["src_port"] if ip["src"] == target_ip
                    else tcp["dst_port"]
                ),
                "streams": defaultdict(bytearray),
            }

        conv = convs[key_s]
        conv["packets"] += 1

        payload = tcp["payload"]
        if payload:
            dedup = (
                ip["src"], tcp["src_port"],
                ip["dst"], tcp["dst_port"],
                tcp["seq"], len(payload),
            )
            if dedup in seen_payloads:
                continue
            seen_payloads.add(dedup)

            direction = (
                "camera_to_peer"
                if ip["src"] == target_ip
                else "peer_to_camera"
            )
            conv["streams"][direction].extend(payload)
            conv["payload_bytes"] += len(payload)

    output = []
    for key_s, conv in convs.items():
        streams = {}
        for direction, data in conv["streams"].items():
            raw = bytes(data)
            streams[direction] = {
                "bytes": len(raw),
                "ascii_preview": _preview(raw),
                "hex_preview": raw[:256].hex(" "),
            }

        output.append({
            "conversation": key_s,
            "endpoint_a": conv["endpoint_a"],
            "endpoint_b": conv["endpoint_b"],
            "camera_port": conv["camera_port"],
            "packets": conv["packets"],
            "payload_bytes": conv["payload_bytes"],
            "streams": streams,
        })

    output.sort(key=lambda x: (x["camera_port"], x["conversation"]))

    return {
        "pcap": str(path),
        "target_ip": target_ip,
        "conversation_count": len(output),
        "conversations": output,
    }
