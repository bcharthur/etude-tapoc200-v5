from __future__ import annotations

import threading
import time

from .raw_capture import capture_windows_ipv4, route_local_ip
from .rtsp import rtsp_baseline
from .onvif import onvif_matrix
from .wsdiscovery import ws_discovery_probe
from .tlsprobe import tls_fingerprint
from .probe8800 import passive_probe_8800
from .pcap import summarize_pcap
from .pcap_conversations import tcp_conversations


def run_recon_with_capture(
    scope,
    run_dir,
    *,
    seconds=15,
    timeout=2.0,
    ws_timeout=2.0,
    passive_wait=2.0,
):
    local_ip = route_local_ip(scope.target_ip)
    pcap = run_dir / "capture.pcap"
    capture_result = {}

    def capture_worker():
        nonlocal capture_result
        capture_result = capture_windows_ipv4(
            local_ip=local_ip,
            target_ip=scope.target_ip,
            output=pcap,
            seconds=seconds,
        )

    thread = threading.Thread(target=capture_worker, daemon=True)
    thread.start()
    time.sleep(0.75)

    recon = {
        "target": {
            "name": scope.device_name,
            "ip": scope.target_ip,
            "mac": scope.target_mac,
            "local_ip": local_ip,
        },
        "rtsp": rtsp_baseline(scope.target_ip, timeout=timeout),
        "ws_discovery": ws_discovery_probe(
            scope.target_ip, local_ip, timeout=ws_timeout
        ),
        "tls_443": tls_fingerprint(
            scope.target_ip, port=443, timeout=timeout
        ),
        "tcp_8800_passive": passive_probe_8800(
            scope.target_ip, wait_seconds=passive_wait
        ),
        "onvif_matrix": onvif_matrix(
            scope.target_ip, timeout=timeout
        ),
    }

    thread.join()

    result = {
        "recon": recon,
        "capture": capture_result,
        "pcap_summary": None,
        "tcp_conversations": None,
    }

    if capture_result.get("ok") and pcap.exists():
        result["pcap_summary"] = summarize_pcap(
            pcap, scope.target_ip
        )
        result["tcp_conversations"] = tcp_conversations(
            pcap, scope.target_ip
        )

    return result
