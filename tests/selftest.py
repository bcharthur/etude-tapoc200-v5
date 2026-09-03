from pathlib import Path
import os
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rootlab.crypto import aes_cfb1, md5crypt
from rootlab.layout import ROOTFS_IV


def main():
    key = b"TP_LINK88i667gnt"
    data = os.urandom(257)
    enc = aes_cfb1(data, key, ROOTFS_IV, decrypt=False)
    dec = aes_cfb1(enc, key, ROOTFS_IV, decrypt=True)
    assert dec == data

    h = md5crypt("test-password", "abc12345")
    assert h.startswith("$1$abc12345$")
    assert len(h.split("$")[-1]) == 22

    print("rootlab self-test: OK")
    print("cfb1 roundtrip:", len(data), "bytes")
    print("md5crypt:", h)


if __name__ == "__main__":
    main()
