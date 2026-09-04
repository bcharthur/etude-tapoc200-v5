from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.diff import compare
from v5patchlab.extract import magic_scan
from v5patchlab.strings import index


def main():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        old = td / "old.bin"
        new = td / "new.bin"

        old.write_bytes(
            b"\x7fELF" + b"\x00" * 128
            + b"device_confirm\x00ciphertext\x00memcpy\x00"
            + b"A" * 128
        )
        new.write_bytes(
            b"\x7fELF" + b"\x00" * 128
            + b"device_confirm\x00ciphertext\x00memcpy\x00MAX_LEN\x00"
            + b"B" * 128
            + b"hsqs"
        )

        d = compare(old, new)
        assert not d["same_file"]
        assert d["changed_run_count"] >= 1
        assert "MAX_LEN" in d["string_delta"]["added"]

        idx = index(new, ["device_confirm", "ciphertext"])
        assert "device_confirm" in idx["hits"]
        assert "ciphertext" in idx["hits"]

        magic = magic_scan(new)
        assert "elf" in magic["magic_hits"]
        assert "squashfs_le" in magic["magic_hits"]

    print("v5patchlab synthetic self-test: OK")


if __name__ == "__main__":
    main()
