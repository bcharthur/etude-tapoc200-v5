from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.camera_fw import CAMERA_READ_REQUESTS, REFRESH_REQUEST
from v5patchlab.publicbase import C200V5_142, info


def main():
    methods = [x["method"] for x in CAMERA_READ_REQUESTS]
    assert "getCloudConfig" in methods
    assert "getFirmwareUpdateStatus" in methods
    assert REFRESH_REQUEST["method"] == "checkFirmwareVersionByCloud"

    row = [x for x in CAMERA_READ_REQUESTS if x["label"] == "upgrade_info"][0]
    assert row["params"]["cloud_config"]["name"] == ["upgrade_info"]

    assert C200V5_142["version"] == "1.4.2"
    assert C200V5_142["build"] == "260513"
    assert C200V5_142["rel"] == "33069n"
    assert C200V5_142["url"].startswith(
        "https://download.tplinkcloud.com/firmware/assigned/"
    )
    assert "1.4.2" in info()["baseline"]["version"]

    print("v1.0.11 noauth self-test: OK")


if __name__ == "__main__":
    main()
