from __future__ import annotations

from .credentials import CameraCredentials
from .rtsp_auth import rtsp_authenticated_matrix
from .onvif_auth import onvif_auth_smoke


def diagnose_auth(
    ip: str,
    creds: CameraCredentials,
    *,
    timeout: float = 3.0,
) -> dict:
    # Basic is intentionally tested here because its result is the clearest
    # credential oracle for the user's own camera. No packet capture is started.
    rtsp = rtsp_authenticated_matrix(
        ip,
        creds,
        also_basic=True,
        timeout=timeout,
    )

    s1 = rtsp["streams"]["stream1"]
    basic_status = (
        s1.get("basic", {}).get("status_line")
        if s1.get("basic")
        else None
    )
    digest_status = (
        s1.get("digest", {}).get("status_line")
        if s1.get("digest")
        else None
    )

    basic_ok = bool(basic_status and " 200 " in basic_status)
    digest_ok = bool(digest_status and " 200 " in digest_status)

    onvif = onvif_auth_smoke(
        ip,
        creds,
        timeout=timeout,
    )

    if basic_ok or digest_ok:
        credential_assessment = "accepted_by_rtsp"
    else:
        credential_assessment = (
            "rejected_by_rtsp: verify Tapo Camera Account username/password"
        )

    return {
        "target_ip": ip,
        "username": creds.username,
        "password_stored": False,
        "credential_assessment": credential_assessment,
        "rtsp_stream1": {
            "basic_status": basic_status,
            "digest_status": digest_status,
            "basic_accepted": basic_ok,
            "digest_accepted": digest_ok,
        },
        "onvif": onvif,
        "interpretation": [
            (
                "If Basic and Digest both return 401, the credential pair is not "
                "accepted by RTSP. Basic does not depend on Digest nonce math."
            ),
            (
                "ONVIF now uses the camera's UTCDateTime specifically; the old "
                "v0.1 parser could incorrectly use LocalDateTime as UTC."
            ),
        ],
    }
