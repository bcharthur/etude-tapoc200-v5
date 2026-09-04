from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.boundcheck import READ_BASELINE
from v5patchlab.cloudcheck import POLL_REQUESTS, TRIGGER_REQUEST


def main():
    rows = READ_BASELINE + POLL_REQUESTS + [TRIGGER_REQUEST]
    blob = repr(rows).lower()

    assert "fw_download" not in blob
    assert "startfirmwareupgrade" not in blob
    assert "reboot" not in blob
    assert "downgrade" not in blob
    assert "checkfirmwareversionbycloud" in blob

    print("bound cloud-check safety self-test: OK")


if __name__ == "__main__":
    main()
