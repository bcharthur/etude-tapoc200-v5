from __future__ import annotations

import socket
import struct
from collections import Counter, defaultdict
from pathlib import Path


def _parse_ipv4(packet: bytes):
    if len(packet) < 20:
        return None

    version = packet[0] >> 4
    ihl = (packet[0] & 0x0F) * 4

    if version != 4 or ihl < 20 or len(packet) < ihl:
        return None

    total_length = struct.unpack("!H", packet[2:4])[0]
    protocol = packet[9]
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])

    return {
        "ihl": ihl,
        "total_length": total_length,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "payload": packet[ihl:total_length] if total_length else packet[ihl:],
    }


def _parse_tcp(payload: bytes):
    if len(payload) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", payload[:4])
    flags = payload[13]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
    }


def _parse_udp(payload: bytes):
    if len(payload) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", payload[:6])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
    }


def iter_pcap_raw_ipv4(path: Path):
    with path.open("rb") as f:
        global_header = f.read(24)
        if len(global_header) != 24:
            raise ValueError("PCAP invalide ou vide.")

        magic = struct.unpack("<I", global_header[:4])[0]
        if magic != 0xA1B2C3D4:
            raise ValueError("PCAP non supporté: endianness/magic inattendu.")

        network = struct.unpack("<I", global_header[20:24])[0]
        if network != 101:
            raise ValueError(f"DLT inattendu: {network}; attendu DLT_RAW=101.")

        while True:
            rec = f.read(16)
            if not rec:
                break
            if len(rec) != 16:
                raise ValueError("Header de paquet PCAP tronqué.")

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec)
            packet = f.read(incl_len)
            if len(packet) != incl_len:
                raise ValueError("Paquet PCAP tronqué.")

            yield {
                "timestamp": ts_sec + ts_usec / 1_000_000,
                "orig_len": orig_len,
                "packet": packet,
            }


def summarize_pcap(path: Path, target_ip: str) -> dict:
    protocol_counts = Counter()
    peer_counts = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    directions = Counter()
    total_packets = 0
    total_bytes = 0

    for record in iter_pcap_raw_ipv4(path):
        ip = _parse_ipv4(record["packet"])
        if not ip:
            continue

        total_packets += 1
        total_bytes += len(record["packet"])

        if ip["src"] == target_ip:
            directions["camera_to_other"] += 1
            peer = ip["dst"]
        elif ip["dst"] == target_ip:
            directions["other_to_camera"] += 1
            peer = ip["src"]
        else:
            continue

        peer_counts[peer] += 1

        if ip["protocol"] == 6:
            protocol_counts["TCP"] += 1
            tcp = _parse_tcp(ip["payload"])
            if tcp:
                camera_port = tcp["src_port"] if ip["src"] == target_ip else tcp["dst_port"]
                tcp_ports[camera_port] += 1

        elif ip["protocol"] == 17:
            protocol_counts["UDP"] += 1
            udp = _parse_udp(ip["payload"])
            if udp:
                camera_port = udp["src_port"] if ip["src"] == target_ip else udp["dst_port"]
                udp_ports[camera_port] += 1
        elif ip["protocol"] == 1:
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts[f"IP_PROTO_{ip['protocol']}"] += 1

    return {
        "pcap": str(path),
        "target_ip": target_ip,
        "total_packets": total_packets,
        "total_ipv4_bytes": total_bytes,
        "directions": dict(directions),
        "protocols": dict(protocol_counts),
        "top_peers": [
            {"ip": ip, "packets": count}
            for ip, count in peer_counts.most_common(20)
        ],
        "camera_tcp_ports": [
            {"port": port, "packets": count}
            for port, count in tcp_ports.most_common()
        ],
        "camera_udp_ports": [
            {"port": port, "packets": count}
            for port, count in udp_ports.most_common()
        ],
    }
