from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.cloudcheck import (
    BASELINE_REQUESTS,
    TRIGGER_REQUEST,
    POLL_REQUESTS,
    _multi_params,
    _label_multiple,
    extract_metadata,
)


def main():
    assert TRIGGER_REQUEST["method"] == "checkFirmwareVersionByCloud"
    assert TRIGGER_REQUEST["params"] == {
        "cloud_config": {"check_fw_version": "null"}
    }

    methods = [r["method"] for r in POLL_REQUESTS]
    assert methods == ["getCloudConfig", "getFirmwareUpdateStatus"]

    # Ensure no camera firmware-install action slipped into this module's
    # request definitions.
    all_rows = BASELINE_REQUESTS + [TRIGGER_REQUEST] + POLL_REQUESTS
    assert all(r["method"] != "do" for r in all_rows)
    assert "fw_download" not in repr(all_rows)

    fake = {
        "error_code": 0,
        "result": {
            "responses": [
                {
                    "method": "getCloudConfig",
                    "error_code": 0,
                    "result": {
                        "cloud_config": {
                            "upgrade_info": {
                                "fw_ver": "1.4.6 Build 260709",
                                "fw_url": (
                                    "https://download.tplinkcloud.com/"
                                    "firmware/example.bin"
                                ),
                                "file_size": 123456,
                                "md5": "abcdef",
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
        },
    }

    labels = _label_multiple(fake, POLL_REQUESTS)
    assert labels["upgrade_info"]["error_code"] == 0

    meta = extract_metadata(fake)
    assert meta["urls"][0]["url"].endswith("example.bin")
    assert any("1.4.6" in x["value"] for x in meta["versions"])
    assert any(x["value"] == 123456 for x in meta["sizes"])
    assert any(x["value"] == "abcdef" for x in meta["hashes"])

    params = _multi_params([TRIGGER_REQUEST])
    assert params["requests"][0]["method"] == "checkFirmwareVersionByCloud"

    print("cloud-check self-test: OK")


if __name__ == "__main__":
    main()
