from __future__ import annotations

import threading
import time

from tapolab.raw_capture import capture_windows_ipv4, route_local_ip
from tapolab.pcap import summarize_pcap
from tapolab.pcap_conversations import tcp_conversations

from .rtsp_auth import rtsp_authenticated_matrix
from .onvif_auth import onvif_authenticated_matrix


def authenticated_capture(
    scope,
    creds,
    run_dir,
    *,
    seconds: int = 20,
    timeout: float = 3.0,
) -> dict:
    local_ip = route_local_ip(scope.target_ip)
    pcap = run_dir / "capture.pcap"
    capture_result = {}

    def worker():
        nonlocal capture_result
        capture_result = capture_windows_ipv4(
            local_ip=local_ip,
            target_ip=scope.target_ip,
            output=pcap,
            seconds=seconds,
        )

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(0.75)

    # Digest RTSP only here: Basic would expose username:password in the PCAP.
    rtsp = rtsp_authenticated_matrix(
        scope.target_ip,
        creds,
        also_basic=False,
        timeout=timeout,
    )

    onvif = onvif_authenticated_matrix(
        scope.target_ip,
        creds,
        timeout=timeout,
    )

    thread.join()

    result = {
        "target": {
            "ip": scope.target_ip,
            "mac": scope.target_mac,
            "local_ip": local_ip,
        },
        "credentials": {
            "username": creds.username,
            "password_stored": False,
        },
        "rtsp_digest": rtsp,
        "onvif_username_token": onvif,
        "capture": capture_result,
        "pcap_summary": None,
        "tcp_conversations": None,
    }

    if capture_result.get("ok") and pcap.exists():
        result["pcap_summary"] = summarize_pcap(pcap, scope.target_ip)
        result["tcp_conversations"] = tcp_conversations(
            pcap, scope.target_ip
        )

    return result
