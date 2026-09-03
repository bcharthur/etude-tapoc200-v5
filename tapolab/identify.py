from .config import Scope
from .windows_net import ping, read_arp_table, discover_ip_by_mac


def identify(scope: Scope, rediscover: bool = False) -> dict:
    reachable = ping(scope.target_ip)
    arp = read_arp_table()
    observed_mac = arp.get(scope.target_ip)

    result = {
        "device_name": scope.device_name,
        "configured_ip": scope.target_ip,
        "expected_mac": scope.target_mac,
        "reachable": reachable,
        "observed_mac": observed_mac,
        "mac_match": observed_mac == scope.target_mac if observed_mac else False,
        "rediscovered_ip": None,
    }

    if rediscover or not observed_mac:
        result["rediscovered_ip"] = discover_ip_by_mac(
            scope.allowed_cidr, scope.target_mac
        )
    return result
