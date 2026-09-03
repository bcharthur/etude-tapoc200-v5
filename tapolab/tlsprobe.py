from __future__ import annotations

import hashlib
import os
import socket
import ssl
import tempfile
import time


def _decode_der_cert(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".pem",
            delete=False,
            encoding="ascii",
        ) as f:
            f.write(pem)
            temp_path = f.name

        # Standard-library decoder used internally by Python's ssl tests/tools.
        return ssl._ssl._test_decode_cert(temp_path)
    except Exception as exc:
        return {"decode_error": f"{type(exc).__name__}: {exc}"}
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def tls_fingerprint(
    ip: str,
    port: int = 443,
    timeout: float = 3.0,
) -> dict:
    result = {
        "ip": ip,
        "port": port,
        "tls": False,
        "version": None,
        "cipher": None,
        "certificate_sha256": None,
        "certificate": None,
        "error": None,
        "elapsed_ms": None,
    }

    started = time.perf_counter()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=None) as tls:
                result["tls"] = True
                result["version"] = tls.version()
                result["cipher"] = tls.cipher()

                der = tls.getpeercert(binary_form=True)
                if der:
                    result["certificate_sha256"] = hashlib.sha256(der).hexdigest()
                    result["certificate"] = _decode_der_cert(der)

    except (ssl.SSLError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result
