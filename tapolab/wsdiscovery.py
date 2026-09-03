from __future__ import annotations

import socket
import time
import uuid
import xml.etree.ElementTree as ET


MULTICAST_ADDR = "239.255.255.250"
MULTICAST_PORT = 3702

NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
}


def _text(node, xpath: str):
    found = node.find(xpath, NS)
    return found.text.strip() if found is not None and found.text else None


def _parse_probe_match(data: bytes) -> dict:
    result = {
        "xml": data.decode("utf-8", errors="replace"),
        "endpoint_reference": None,
        "types": None,
        "scopes": None,
        "xaddrs": None,
        "metadata_version": None,
        "parse_error": None,
    }
    try:
        root = ET.fromstring(data)
        match = root.find(".//d:ProbeMatch", NS)
        if match is None:
            return result

        result["endpoint_reference"] = _text(
            match, ".//a:EndpointReference/a:Address"
        )
        result["types"] = _text(match, "d:Types")
        result["scopes"] = _text(match, "d:Scopes")
        result["xaddrs"] = _text(match, "d:XAddrs")
        result["metadata_version"] = _text(match, "d:MetadataVersion")
    except ET.ParseError as exc:
        result["parse_error"] = str(exc)
    return result


def ws_discovery_probe(
    target_ip: str,
    local_ip: str,
    timeout: float = 2.0,
) -> dict:
    """
    Sends one standard ONVIF/WS-Discovery Probe to the multicast group and
    records only responses originating from target_ip.
    """
    message_id = f"uuid:{uuid.uuid4()}"

    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>""".encode("utf-8")

    responses = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    try:
        sock.settimeout(0.25)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(local_ip),
        )
        sock.bind((local_ip, 0))
        sock.sendto(payload, (MULTICAST_ADDR, MULTICAST_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue

            if peer[0] != target_ip:
                continue

            parsed = _parse_probe_match(data)
            parsed["peer"] = {"ip": peer[0], "port": peer[1]}
            responses.append(parsed)
    finally:
        sock.close()

    return {
        "target_ip": target_ip,
        "local_ip": local_ip,
        "multicast": f"{MULTICAST_ADDR}:{MULTICAST_PORT}",
        "message_id": message_id,
        "responses": responses,
        "response_count": len(responses),
    }
