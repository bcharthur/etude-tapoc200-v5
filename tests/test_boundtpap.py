from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.boundcrypto import (
    md5_crypt,
    sha256_crypt,
    resolve_credential,
    select_candidate,
)


def openssl(*args):
    cp = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr)
    return cp.stdout.strip()


def main():
    assert md5_crypt("password", "$1$salt$") == openssl(
        "passwd", "-1", "-salt", "salt", "password"
    )
    assert sha256_crypt("password", "$5$salt$") == openssl(
        "passwd", "-5", "-salt", "salt", "password"
    )

    assert select_candidate("Abc", "raw") == "Abc"
    assert len(select_candidate("Abc", "md5")) == 32
    assert len(select_candidate("Abc", "sha256")) == 64

    value, meta = resolve_credential(
        "password",
        mac="DC62798B3ADA",
        extra_crypt={
            "type": "password_shadow",
            "params": {"passwd_id": "2", "passwd_prefix": ""},
        },
    )
    assert value == __import__("hashlib").sha1(b"password").hexdigest()
    assert meta["transform"] == "sha1"

    value, meta = resolve_credential(
        "password",
        mac="DC62798B3ADA",
        extra_crypt={
            "type": "password_sha_with_salt",
            "params": {"sha_name": "0", "sha_salt": "AQIDBA=="},
        },
    )
    assert len(value) == 64

    print("bound TPAP crypto self-test: OK")


if __name__ == "__main__":
    main()
