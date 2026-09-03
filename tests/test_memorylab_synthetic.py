from pathlib import Path
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from memstate.flash import flash_diff
from memstate.uart import analyze_uart


def main():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        a = bytearray(b"\xff" * (8 * 1024 * 1024))
        b = bytearray(a)

        # Change bytes inside config partition.
        b[0x040100:0x040108] = b"SETUP123"

        (td / "a.bin").write_bytes(a)
        (td / "b.bin").write_bytes(b)

        result = flash_diff(
            str(td / "a.bin"),
            str(td / "b.bin"),
            str(td / "diff"),
            str(PROJECT_ROOT / "config/c200v5_partitions.json"),
        )

        assert result["changed_byte_count"] > 0
        assert result["partition_stats"]["config"]["changed_bytes"] > 0

        log = td / "uart.jsonl"
        log.write_text(
            '{"ts":"x","text":"Kernel panic - not syncing"}\n'
            '{"ts":"x","text":"EPC : 80401234 RA : 80400000"}\n'
            '{"ts":"x","text":"watchdog reboot"}\n',
            encoding="utf-8",
        )

        ua = analyze_uart(str(log))
        assert ua["classification"]["kernel_oops_seen"]
        assert ua["classification"]["watchdog_seen"]

    print("synthetic self-test: OK")


if __name__ == "__main__":
    main()
