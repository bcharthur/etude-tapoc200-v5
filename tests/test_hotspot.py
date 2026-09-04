from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.hotspot import (
    _find_ap_list_and_key,
    _safe_ap_summary,
    _encrypt_wifi_password,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def main():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    fake = {
        "result": {
            "responses": [
                {
                    "result": {
                        "onboarding": {
                            "ap_list": [
                                {
                                    "ssid": "iPhone Arthur",
                                    "bssid": "AA:BB:CC:DD:EE:FF",
                                    "rssi": -34,
                                    "key_type": "wpa2_psk",
                                }
                            ],
                            "public_key": pem,
                        }
                    }
                }
            ]
        }
    }

    aps, pub = _find_ap_list_and_key(fake)
    assert len(aps) == 1
    assert aps[0]["ssid"] == "iPhone Arthur"
    assert pub.startswith("-----BEGIN PUBLIC KEY-----")

    safe = _safe_ap_summary(aps[0])
    assert "bssid" not in safe
    assert safe["ssid"] == "iPhone Arthur"

    ciphertext = _encrypt_wifi_password(
        pub,
        "synthetic-password",
    )
    assert isinstance(ciphertext, str)
    assert len(ciphertext) > 100

    print("hotspot onboarding self-test: OK")


if __name__ == "__main__":
    main()
