from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.normalcheck import (
    CHECK_REQUESTS,
    _label_responses,
    extract_metadata,
)


def main():
    methods = [x["method"] for x in CHECK_REQUESTS]
    assert "checkFirmwareVersionByCloud" in methods
    assert "getCloudConfig" in methods
    assert "getFirmwareUpdateStatus" in methods

    text = repr(CHECK_REQUESTS)
    assert "fw_download" not in text
    assert "startFirmwareUpgrade" not in text

    fake = {
        "result": {
            "responses": [
                {
                    "method": "checkFirmwareVersionByCloud",
                    "error_code": 0,
                    "result": {},
                },
                {
                    "method": "getCloudConfig",
                    "error_code": 0,
                    "result": {
                        "cloud_config": {
                            "upgrade_info": {
                                "fw_ver": "1.4.6 Build 260709",
                                "url": "https://download.tplinkcloud.com/firmware/x.bin",
                                "file_size": 42,
                                "sha256": "deadbeef",
                            }
                        }
                    },
                },
                {
                    "method": "getFirmwareUpdateStatus",
                    "error_code": 0,
                    "result": {
                        "cloud_config": {
                            "upgrade_status": {"state": "normal"}
                        }
                    },
                },
            ]
        }
    }

    labeled = _label_responses(fake, CHECK_REQUESTS)
    assert labeled["upgrade_info"]["error_code"] == 0

    meta = extract_metadata(fake)
    assert meta["urls"][0]["url"].endswith("/x.bin")
    assert any(x["value"] == 42 for x in meta["sizes"])
    assert any(x["value"] == "deadbeef" for x in meta["hashes"])

    print("normal-cloud-check self-test: OK")


if __name__ == "__main__":
    main()
