from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.camera_fw import (
    CAMERA_READ_REQUESTS,
    build_multiple_request,
    _label_responses,
)


def main():
    req = build_multiple_request()
    assert len(req["requests"]) == 4
    assert req["requests"][0]["method"] == "getDeviceInfo"
    assert req["requests"][0]["params"] == {
        "device_info": {"name": ["basic_info"]}
    }
    assert req["requests"][1]["method"] == "getFirmwareUpdateStatus"
    assert req["requests"][1]["params"] == {
        "cloud_config": {"name": "upgrade_status"}
    }

    fake = {
        "error_code": 0,
        "result": {
            "responses": [
                {"method": "getDeviceInfo", "error_code": 0},
                {"method": "getFirmwareUpdateStatus", "error_code": 0},
                {"method": "getFirmwareAutoUpgradeConfig", "error_code": 0},
                {"method": "getClockStatus", "error_code": 0},
            ]
        },
    }
    labeled = _label_responses(fake)
    assert labeled["device_info"]["error_code"] == 0
    assert labeled["firmware_update_status"]["error_code"] == 0

    print("camera multipleRequest self-test: OK")


if __name__ == "__main__":
    main()
