from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.cloudaccount import (
    redact,
    _choose_scoped_camera,
    _collect_urls,
    _interesting_fw_fields,
    FW_METHOD_TRIGGER,
    FW_METHODS_READ,
)


def main():
    assert FW_METHOD_TRIGGER["method"] == "checkFirmwareVersionByCloud"
    assert [x["method"] for x in FW_METHODS_READ] == [
        "getCloudConfig",
        "getFirmwareUpdateStatus",
    ]

    dev = {
        "deviceId": "secret-device-id",
        "deviceMac": "DC62798B3ADA",
        "deviceModel": "C200",
        "deviceHwVer": "5.0",
        "fwVer": "1.4.6 Build 260709 Rel.27675n",
        "fwId": "DUMMYFWID",
    }
    chosen = _choose_scoped_camera([dev], "dc:62:79:8b:3a:da")
    assert chosen is dev

    sample = {
        "token": "secret",
        "result": {
            "upgrade_info": {
                "download_url": "https://download.tplinkcloud.com/firmware/a.bin",
                "version": "1.4.6",
            }
        }
    }
    safe = redact(sample)
    assert safe["token"] == "<redacted>"
    assert _collect_urls(sample) == [
        "https://download.tplinkcloud.com/firmware/a.bin"
    ]
    fields = _interesting_fw_fields(sample)
    assert any(x["path"].endswith("download_url") for x in fields)
    assert any(x["path"].endswith("version") for x in fields)

    print("cloud-account-fw self-test: OK")


if __name__ == "__main__":
    main()
