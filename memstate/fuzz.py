from __future__ import annotations

import hashlib
import socket
import time

from .network import tcp_probe
from .scope import load_scope
from .preflight import require_scoped_service


DEFAULT_LENGTHS = [
    0, 1, 7, 15, 31, 32, 63, 64, 127, 128,
    255, 256, 511, 512, 1023, 1024, 2047, 2048,
    4095, 4096, 8191
]


def _alive(ip):
    return any(
        tcp_probe(ip, p, timeout=0.35)["open"]
        for p in (443, 554, 2020, 8800)
    )


def _recv_head(sock, max_bytes=16384):
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        try:
            c = sock.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        data.extend(c)
    return bytes(data)


def _armed(arm: bool):
    if not arm:
        raise RuntimeError(
            "Crash-oriented parser probes are disabled by default. "
            "Re-run with --arm on your scoped camera."
        )


def rtsp_authorization_fuzz(*, arm: bool, lengths=None, delay=0.3):
    _armed(arm)
    preflight = require_scoped_service("rtsp")
    scope = load_scope()
    ip = scope.target_ip
    lengths = lengths or DEFAULT_LENGTHS

    rows = []

    for n in lengths:
        marker = "A" * n
        header = f'Authorization: Digest username="{marker}"'
        req = (
            "DESCRIBE rtsp://%s/stream1 RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "%s\r\n\r\n"
        ) % (ip, header)

        before = _alive(ip)
        if not before:
            raise RuntimeError(
                f"Target became unavailable before case length={n}; "
                "stopping before sending the testcase."
            )

        started = time.perf_counter()
        status = None
        error = None

        try:
            with socket.create_connection((ip, 554), timeout=1.0) as s:
                s.settimeout(1.0)
                s.sendall(req.encode("ascii", errors="ignore"))
                raw = _recv_head(s)
                lines = raw.decode("latin-1", errors="replace").splitlines()
                status = lines[0] if lines else None
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        time.sleep(delay)
        after = _alive(ip)

        row = {
            "case": "rtsp_digest_username_length",
            "length": n,
            "request_sha256": hashlib.sha256(req.encode()).hexdigest(),
            "status_line": status,
            "error": error,
            "elapsed_ms": round((time.perf_counter()-started)*1000, 2),
            "target_alive_before": before,
            "target_alive_after": after,
        }
        rows.append(row)

        if before and not after:
            row["crash_candidate"] = True
            row["stop_reason"] = "target became unavailable"
            break

    return {
        "target_ip": ip,
        "armed": True,
        "preflight": preflight,
        "case_count": len(rows),
        "rows": rows,
    }


def streamd_boundary_fuzz(*, arm: bool, lengths=None, delay=0.3):
    _armed(arm)
    preflight = require_scoped_service("streamd")
    scope = load_scope()
    ip = scope.target_ip
    lengths = lengths or [
        0,1,31,32,63,64,127,128,255,256,511,512,1024,2048,4096
    ]

    rows = []

    for n in lengths:
        boundary = "B" * n
        req = (
            "POST /stream HTTP/1.1\r\n"
            f"Host: {ip}:8800\r\n"
            f"Content-Type: multipart/mixed; boundary={boundary}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

        before = _alive(ip)
        if not before:
            raise RuntimeError(
                f"Target became unavailable before case length={n}; stopping."
            )

        status = None
        error = None

        try:
            with socket.create_connection((ip, 8800), timeout=1.0) as s:
                s.settimeout(1.0)
                s.sendall(req)
                raw = _recv_head(s)
                lines = raw.decode("latin-1", errors="replace").splitlines()
                status = lines[0] if lines else None
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        time.sleep(delay)
        after = _alive(ip)

        row = {
            "case": "streamd_boundary_length",
            "length": n,
            "request_sha256": hashlib.sha256(req).hexdigest(),
            "status_line": status,
            "error": error,
            "target_alive_before": before,
            "target_alive_after": after,
        }
        rows.append(row)

        if before and not after:
            row["crash_candidate"] = True
            row["stop_reason"] = "target became unavailable"
            break

    return {
        "target_ip": ip,
        "armed": True,
        "preflight": preflight,
        "case_count": len(rows),
        "rows": rows,
    }


def https_json_fuzz(*, arm: bool, lengths=None, delay=0.3):
    _armed(arm)
    preflight = require_scoped_service("https")

    import json
    import ssl

    scope = load_scope()
    ip = scope.target_ip
    lengths = lengths or [
        0,1,31,32,63,64,127,128,255,256,511,512,1024,2048,4096
    ]

    rows = []

    for n in lengths:
        method = "M" * n
        body = json.dumps({
            "method": method,
            "params": {"sub_method": "discover"},
        }, separators=(",", ":")).encode()

        req = (
            "POST / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body

        before = _alive(ip)
        if not before:
            raise RuntimeError(
                f"Target became unavailable before case length={n}; stopping."
            )

        status = None
        error = None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, 443), timeout=1.0) as raw:
                raw.settimeout(1.0)
                with ctx.wrap_socket(raw, server_hostname=None) as s:
                    s.sendall(req)
                    resp = _recv_head(s)
                    lines = resp.decode("latin-1", errors="replace").splitlines()
                    status = lines[0] if lines else None
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        time.sleep(delay)
        after = _alive(ip)

        row = {
            "case": "https_json_method_length",
            "length": n,
            "request_sha256": hashlib.sha256(req).hexdigest(),
            "status_line": status,
            "error": error,
            "target_alive_before": before,
            "target_alive_after": after,
        }
        rows.append(row)

        if before and not after:
            row["crash_candidate"] = True
            row["stop_reason"] = "target became unavailable"
            break

    return {
        "target_ip": ip,
        "armed": True,
        "preflight": preflight,
        "case_count": len(rows),
        "rows": rows,
    }
