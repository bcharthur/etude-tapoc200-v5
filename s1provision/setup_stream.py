from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tapolab.config import load_scope

from .wifi_windows import connected_wifi
from .netstate import ip_configurations


# Boundary parameter values advertised in Content-Type.
CLIENT_BOUNDARY_VALUE = b"--client-stream-boundary--"
DEVICE_BOUNDARY_VALUE = b"--device-stream-boundary--"

# MIME wire delimiter = "--" + boundary parameter value.
CLIENT_WIRE_BOUNDARY = b"----client-stream-boundary--"
DEVICE_WIRE_BOUNDARY = b"----device-stream-boundary--"

SETUP_STREAM_SECRET = "TPL075526460603"


def _private_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        a = ipaddress.ip_address(value)
        return a.version == 4 and a.is_private
    except ValueError:
        return False


def _wifi_config(configs: list[dict]) -> dict | None:
    for row in configs:
        alias = (row.get("InterfaceAlias") or "").lower()
        if "wi-fi" in alias or "wifi" in alias or "wlan" in alias:
            return row
    return None


def _setup_target() -> tuple[str | None, dict]:
    scope = load_scope()
    wifi = connected_wifi()
    ssid = wifi.get("ssid") or ""

    expected_suffix = (
        scope.target_mac.replace(":", "").replace("-", "")[-4:].upper()
    )
    expected_ssid = f"Tapo_Cam_{expected_suffix}"

    gate = {
        "connected_wifi": wifi,
        "expected_setup_ssid": expected_ssid,
        "ssid_matches_scoped_camera": ssid.upper() == expected_ssid.upper(),
        "candidate_ip": None,
        "error": None,
    }

    if not gate["ssid_matches_scoped_camera"]:
        gate["error"] = (
            f"Refusing: connected SSID is not the scoped camera setup SSID "
            f"{expected_ssid!r}."
        )
        return None, gate

    configs = ip_configurations()
    if not configs.get("ok"):
        gate["error"] = configs.get("error")
        return None, gate

    row = _wifi_config(configs.get("interfaces") or [])
    if not row:
        gate["error"] = "Could not identify Wi-Fi IP configuration."
        return None, gate

    gateways = row.get("IPv4DefaultGateway") or []
    target = next((x for x in gateways if _private_ipv4(x)), None)

    if not target:
        gate["error"] = "No private default gateway on setup Wi-Fi."
        return None, gate

    gate["candidate_ip"] = target
    return target, gate


def _parse_headers(block: bytes) -> dict:
    headers = {}
    for line in block.decode("latin-1", errors="replace").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.setdefault(k.strip().lower(), []).append(v.strip())
    return headers


def _parse_http_response_head(head: bytes) -> tuple[str | None, dict]:
    lines = head.decode("latin-1", errors="replace").splitlines()
    status = lines[0] if lines else None
    headers = _parse_headers(b"\r\n".join(
        line.encode("latin-1", errors="replace")
        for line in lines[1:]
    ))
    return status, headers


def _key_exchange_params(value: str | None) -> dict:
    import re
    result = {}
    if not value:
        return result
    for key, val in re.findall(r'([A-Za-z0-9_-]+)="([^"]*)"', value):
        result[key.lower()] = val
    return result


def _derive_stream_crypto(nonce: str, username: str, password: str):
    key = hashlib.md5(f"{nonce}:{password}".encode()).digest()
    iv = hashlib.md5(f"{username}:{nonce}".encode()).digest()
    return key, iv


def _decrypt_part(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    if not ciphertext or len(ciphertext) % 16:
        return None
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


def _ts_sync_score(data: bytes) -> dict:
    best = {"offset": None, "consecutive_syncs": 0}
    for offset in range(min(188, len(data))):
        count = 0
        pos = offset
        while pos < len(data) and data[pos] == 0x47:
            count += 1
            pos += 188
        if count > best["consecutive_syncs"]:
            best = {"offset": offset, "consecutive_syncs": count}
    return best


class BufferedSocket:
    def __init__(self, sock: socket.socket, initial: bytes = b""):
        self.sock = sock
        self.buf = bytearray(initial)

    def _fill(self, minimum: int = 1):
        while len(self.buf) < minimum:
            chunk = self.sock.recv(16384)
            if not chunk:
                raise EOFError("socket closed")
            self.buf.extend(chunk)

    def read_until(self, marker: bytes, max_bytes: int = 131072) -> bytes:
        while True:
            idx = self.buf.find(marker)
            if idx >= 0:
                out = bytes(self.buf[:idx])
                del self.buf[:idx + len(marker)]
                return out
            if len(self.buf) >= max_bytes:
                raise RuntimeError(f"marker not found before {max_bytes} bytes")
            chunk = self.sock.recv(16384)
            if not chunk:
                raise EOFError("socket closed before marker")
            self.buf.extend(chunk)

    def read_exact(self, n: int) -> bytes:
        self._fill(n)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def discard_crlf(self):
        while self.buf.startswith(b"\r\n"):
            del self.buf[:2]


def _read_multipart_part(reader: BufferedSocket) -> dict:
    # Seek next real MIME delimiter.
    reader.read_until(DEVICE_WIRE_BOUNDARY)
    reader.discard_crlf()

    header_block = reader.read_until(b"\r\n\r\n")
    headers = _parse_headers(header_block)

    values = headers.get("content-length") or []
    if not values:
        raise RuntimeError("multipart part has no Content-Length")

    try:
        length = int(values[-1])
    except ValueError as exc:
        raise RuntimeError("invalid multipart Content-Length") from exc

    body = reader.read_exact(length)

    # The next bytes are usually CRLF before the next boundary.
    reader.discard_crlf()

    return {
        "headers": headers,
        "body": body,
    }


def setup_stream_smoke(
    *,
    timeout: float = 4.0,
    max_parts: int = 8,
    max_video_bytes: int = 262144,
) -> dict:
    target, gate = _setup_target()

    out = {
        "scope_gate": gate,
        "target_ip": target,
        "credentials_supplied_by_user": False,
        "authorization_header_sent": False,
        "historical_setup_secret_attempted": False,
        "wire_boundary_fix": True,
        "handshake": None,
        "preview_request": None,
        "session_response": None,
        "parts": [],
        "media_observed": False,
        "decryptable_mpeg_ts_observed": False,
        "error": None,
        "note": (
            "No media is written to disk. Only a bounded first-video-part smoke "
            "test is performed."
        ),
    }

    if not target:
        out["error"] = gate.get("error")
        return out

    started = time.perf_counter()

    try:
        with socket.create_connection((target, 8800), timeout=timeout) as s:
            s.settimeout(timeout)

            # Match current Tapo clients: streaming POST with multipart boundary.
            http_req = (
                "POST /stream HTTP/1.1\r\n"
                f"Host: {target}:8800\r\n"
                "Content-Type: multipart/mixed; boundary=--client-stream-boundary--\r\n"
                "User-Agent: tapolab-s1/0.8.1\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: -1\r\n"
                "\r\n"
            ).encode("ascii")

            s.sendall(http_req)

            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < 65536:
                chunk = s.recv(8192)
                if not chunk:
                    break
                raw.extend(chunk)

            head, sep, remainder = bytes(raw).partition(b"\r\n\r\n")
            if not sep:
                raise RuntimeError("incomplete Streamd HTTP response")

            status, headers = _parse_http_response_head(head)
            exchange = (headers.get("key-exchange") or [None])[-1]
            params = _key_exchange_params(exchange)

            out["handshake"] = {
                "status_line": status,
                "server": (headers.get("server") or [None])[-1],
                "content_type": (headers.get("content-type") or [None])[-1],
                "x_session_id_header": (
                    headers.get("x-session-id") or [None]
                )[-1],
                "key_exchange": {
                    "cipher": params.get("cipher"),
                    "username": params.get("username"),
                    "padding": params.get("padding"),
                    "algorithm": params.get("algorithm"),
                    "encrypt_type": params.get("encrypt_type"),
                    "nonce_present": bool(params.get("nonce")),
                    "nonce_length": len(params.get("nonce") or ""),
                },
            }

            if not status or " 200 " not in status:
                raise RuntimeError(f"unexpected Streamd status: {status}")

            if params.get("username") != "none":
                raise RuntimeError(
                    "Streamd did not advertise username='none'; refusing default-secret path"
                )

            nonce = params.get("nonce")
            if not nonce:
                raise RuntimeError("missing Streamd nonce")

            key, iv = _derive_stream_crypto(
                nonce,
                "none",
                SETUP_STREAM_SECRET,
            )
            out["historical_setup_secret_attempted"] = True

            preview = {
                "params": {
                    "preview": {
                        "audio": ["default"],
                        "channels": [0],
                        "resolutions": ["HD"],
                    },
                    "method": "get",
                },
                "seq": 1,
                "type": "request",
            }
            payload = json.dumps(preview, separators=(",", ":")).encode()

            # Important: boundary VALUE starts with "--"; MIME adds another "--".
            # So actual wire delimiter starts with FOUR hyphens.
            wire_part = (
                CLIENT_WIRE_BOUNDARY
                + b"\r\n"
                + b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                + b"\r\n"
                + payload
                + b"\r\n"
            )

            out["preview_request"] = {
                "json_bytes": len(payload),
                "wire_bytes": len(wire_part),
                "wire_boundary": CLIENT_WIRE_BOUNDARY.decode(),
                "seq": 1,
                "channel": 0,
                "resolution": "HD",
            }

            s.sendall(wire_part)

            reader = BufferedSocket(s, remainder)

            for index in range(max_parts):
                try:
                    part = _read_multipart_part(reader)
                except (socket.timeout, EOFError):
                    break

                ph = part["headers"]
                body = part["body"]
                ctype = (ph.get("content-type") or [""])[-1]
                encrypted = (ph.get("x-if-encrypt") or ["0"])[-1] == "1"
                sid = (ph.get("x-session-id") or [None])[-1]

                summary = {
                    "index": index,
                    "content_type": ctype,
                    "content_length": len(body),
                    "x_if_encrypt": encrypted,
                    "x_session_id": sid,
                }

                if ctype == "application/json":
                    parsed = None
                    try:
                        parsed = json.loads(body.decode("utf-8"))
                    except Exception:
                        pass

                    summary["json"] = parsed
                    summary["ascii_preview"] = (
                        None if parsed is not None
                        else body[:512].decode("utf-8", errors="replace")
                    )

                    if out["session_response"] is None and isinstance(parsed, dict):
                        params_obj = parsed.get("params")
                        if isinstance(params_obj, dict):
                            out["session_response"] = {
                                "error_code": params_obj.get("error_code"),
                                "session_id": params_obj.get("session_id"),
                                "type": parsed.get("type"),
                                "seq": parsed.get("seq"),
                            }

                elif ctype == "video/mp2t":
                    out["media_observed"] = True

                    limited = body[:max_video_bytes]
                    plain = _decrypt_part(limited, key, iv) if encrypted else limited
                    sync = _ts_sync_score(plain or b"")

                    summary["ciphertext_bytes_tested"] = len(limited)
                    summary["decryption_succeeded"] = plain is not None
                    summary["plaintext_bytes"] = len(plain or b"")
                    summary["mpeg_ts_sync"] = sync
                    summary["mpeg_ts_likely"] = (
                        sync["consecutive_syncs"] >= 3
                    )
                    summary["plaintext_sha256"] = (
                        hashlib.sha256(plain).hexdigest()
                        if plain else None
                    )

                    if summary["mpeg_ts_likely"]:
                        out["decryptable_mpeg_ts_observed"] = True

                    out["parts"].append(summary)
                    break

                out["parts"].append(summary)

    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"

    out["elapsed_ms"] = round(
        (time.perf_counter() - started) * 1000,
        2,
    )
    return out
