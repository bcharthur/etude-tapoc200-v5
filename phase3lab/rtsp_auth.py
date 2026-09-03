from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import time
from urllib.parse import urlparse

from .credentials import CameraCredentials


AUTH_RE = re.compile(
    r'^\s*(Basic|Digest)\s+(.*)$',
    re.I,
)
PARAM_RE = re.compile(
    r'([A-Za-z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^,\s]+)'
)


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _parse_challenge(value: str) -> dict:
    m = AUTH_RE.match(value)
    if not m:
        return {"scheme": None, "params": {}, "raw": value}

    scheme = m.group(1)
    rest = m.group(2)
    params = {}

    for pm in PARAM_RE.finditer(rest):
        key = pm.group(1).lower()
        val = pm.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        params[key] = val

    return {
        "scheme": scheme,
        "params": params,
        "raw": value,
    }


def _read_rtsp_response(sock: socket.socket, max_bytes: int = 262144) -> tuple[str, bytes]:
    buffer = bytearray()

    while b"\r\n\r\n" not in buffer and len(buffer) < max_bytes:
        data = sock.recv(8192)
        if not data:
            break
        buffer.extend(data)

    raw = bytes(buffer)
    head, sep, body = raw.partition(b"\r\n\r\n")

    content_length = 0
    for line in head.decode("latin-1", errors="replace").splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                pass

    while len(body) < content_length and len(raw) < max_bytes:
        data = sock.recv(min(8192, content_length - len(body)))
        if not data:
            break
        raw += data
        head, sep, body = raw.partition(b"\r\n\r\n")

    return head.decode("latin-1", errors="replace"), body[:content_length] if content_length else body


def _request(ip: str, port: int, request: bytes, timeout: float = 3.0) -> dict:
    started = time.perf_counter()
    result = {
        "status_line": None,
        "headers": {},
        "header_lines": [],
        "body": None,
        "error": None,
        "elapsed_ms": None,
    }

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)
            head, body = _read_rtsp_response(s)

        lines = head.splitlines()
        if lines:
            result["status_line"] = lines[0]

        headers = {}
        header_lines = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            headers.setdefault(key, []).append(value)
            header_lines.append({"name": key, "value": value})

        result["headers"] = headers
        result["header_lines"] = header_lines
        result["body"] = body.decode("utf-8", errors="replace") if body else None

    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def _challenge_for_stream(ip: str, stream: str, timeout: float) -> dict:
    uri = f"rtsp://{ip}:554/{stream}"
    request = (
        f"DESCRIBE {uri} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: tapolab-phase3/0.1\r\n"
        "\r\n"
    ).encode("ascii")

    result = _request(ip, 554, request, timeout)
    challenges = []

    for value in result.get("headers", {}).get("www-authenticate", []):
        challenges.append(_parse_challenge(value))

    result["auth_challenges"] = challenges
    result["uri"] = uri
    return result


def _digest_authorization(
    creds: CameraCredentials,
    method: str,
    uri: str,
    challenge: dict,
) -> str:
    params = challenge["params"]
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    algorithm = params.get("algorithm", "MD5").upper()
    qop_raw = params.get("qop")

    if algorithm not in {"MD5", "MD5-SESS"}:
        raise RuntimeError(f"Algorithme Digest non supporté par ce lab: {algorithm}")

    ha1 = _md5_hex(f"{creds.username}:{realm}:{creds.password}")

    cnonce = os.urandom(8).hex()
    if algorithm == "MD5-SESS":
        ha1 = _md5_hex(f"{ha1}:{nonce}:{cnonce}")

    ha2 = _md5_hex(f"{method}:{uri}")

    fields = [
        f'username="{creds.username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
    ]

    if qop_raw:
        qops = [x.strip() for x in qop_raw.split(",")]
        qop = "auth" if "auth" in qops else qops[0]
        nc = "00000001"
        response = _md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        fields.extend([
            f'response="{response}"',
            f"qop={qop}",
            f"nc={nc}",
            f'cnonce="{cnonce}"',
        ])
    else:
        response = _md5_hex(f"{ha1}:{nonce}:{ha2}")
        fields.append(f'response="{response}"')

    if params.get("opaque"):
        fields.append(f'opaque="{params["opaque"]}"')

    if params.get("algorithm"):
        fields.append(f"algorithm={params['algorithm']}")

    return "Digest " + ", ".join(fields)


def _basic_authorization(creds: CameraCredentials) -> str:
    raw = f"{creds.username}:{creds.password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _authenticated_describe(
    ip: str,
    stream: str,
    creds: CameraCredentials,
    scheme: str,
    challenge: dict,
    timeout: float,
) -> dict:
    uri = f"rtsp://{ip}:554/{stream}"

    if scheme.lower() == "digest":
        auth = _digest_authorization(creds, "DESCRIBE", uri, challenge)
    elif scheme.lower() == "basic":
        auth = _basic_authorization(creds)
    else:
        raise ValueError(scheme)

    request = (
        f"DESCRIBE {uri} RTSP/1.0\r\n"
        "CSeq: 2\r\n"
        "Accept: application/sdp\r\n"
        f"Authorization: {auth}\r\n"
        "User-Agent: tapolab-phase3/0.1\r\n"
        "\r\n"
    ).encode("utf-8")

    result = _request(ip, 554, request, timeout)

    # Never store credentials/authentication material in JSON evidence.
    result["request_redacted"] = (
        f"DESCRIBE {uri} RTSP/1.0\r\n"
        "CSeq: 2\r\n"
        "Accept: application/sdp\r\n"
        f"Authorization: {scheme} <redacted>\r\n"
        "User-Agent: tapolab-phase3/0.1\r\n\r\n"
    )
    result["scheme"] = scheme
    return result


def parse_sdp(body: str | None) -> dict:
    if not body:
        return {
            "media": [],
            "rtpmap": [],
            "fmtp": [],
            "control": [],
            "raw": None,
        }

    media = []
    rtpmap = []
    fmtp = []
    control = []

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith("m="):
            media.append(line[2:])
        elif line.startswith("a=rtpmap:"):
            rtpmap.append(line[len("a=rtpmap:"):])
        elif line.startswith("a=fmtp:"):
            fmtp.append(line[len("a=fmtp:"):])
        elif line.startswith("a=control:"):
            control.append(line[len("a=control:"):])

    return {
        "media": media,
        "rtpmap": rtpmap,
        "fmtp": fmtp,
        "control": control,
        "raw": body,
    }


def rtsp_authenticated_matrix(
    ip: str,
    creds: CameraCredentials,
    *,
    also_basic: bool = False,
    timeout: float = 3.0,
) -> dict:
    streams = {}

    for stream in ("stream1", "stream2"):
        challenge_result = _challenge_for_stream(ip, stream, timeout)
        challenges = challenge_result.get("auth_challenges", [])

        digest = next(
            (c for c in challenges if (c.get("scheme") or "").lower() == "digest"),
            None,
        )
        basic = next(
            (c for c in challenges if (c.get("scheme") or "").lower() == "basic"),
            None,
        )

        stream_result = {
            "challenge_status": challenge_result.get("status_line"),
            "advertised_schemes": [c.get("scheme") for c in challenges],
            "digest": None,
            "basic": None,
        }

        if digest:
            auth_result = _authenticated_describe(
                ip, stream, creds, "Digest", digest, timeout
            )
            auth_result["sdp"] = parse_sdp(auth_result.get("body"))
            stream_result["digest"] = auth_result

        if also_basic and basic:
            auth_result = _authenticated_describe(
                ip, stream, creds, "Basic", basic, timeout
            )
            auth_result["sdp"] = parse_sdp(auth_result.get("body"))
            stream_result["basic"] = auth_result

        streams[stream] = stream_result

    return {
        "target_ip": ip,
        "username": creds.username,
        "password_stored": False,
        "basic_test_requested": also_basic,
        "warning": (
            "Basic transporte username:password encodé en Base64 sur RTSP non chiffré. "
            "Ne lance pas --also-basic pendant une capture que tu comptes partager."
            if also_basic else None
        ),
        "streams": streams,
    }
