# V5PatchLab v1.0.4 — cloud firmware metadata check

## Purpose

The v1.0.3 run proved that the C200 V5 accepts camera-style `multipleRequest`
over the SETUP TPAP session and returns:

```text
getDeviceInfo                 error_code 0
getFirmwareUpdateStatus       error_code 0
getFirmwareAutoUpgradeConfig  error_code 0
getClockStatus                error_code 0
```

`getFirmwareUpdateStatus` only exposes the local upgrade state. It does not
itself ask the vendor cloud whether a newer package exists.

Public Tapo camera implementations use the following pair for the actual
availability/metadata check:

```text
checkFirmwareVersionByCloud
    cloud_config.check_fw_version = "null"

getCloudConfig
    cloud_config.name = ["upgrade_info"]
```

v1.0.4 implements that flow while explicitly excluding `fw_download`.

## Recommended command

Remain connected to the exact scoped setup network:

```text
Tapo_Cam_3ADA
```

Then run:

```powershell
python .\v5patchlab.py cloud-check `
  --poll-seconds 20 `
  --interval 2
```

The flow is:

```text
1. authenticate TPAP pake:[0]
2. baseline:
     getDeviceInfo
     getCloudConfig(upgrade_info)
     getFirmwareUpdateStatus
     getClockStatus
3. send ONE:
     checkFirmwareVersionByCloud
4. poll:
     getCloudConfig(upgrade_info)
     getFirmwareUpdateStatus
5. extract:
     URL
     firmware/version/build fields
     hashes
     sizes
     filenames/package names
     states/statuses
```

Evidence is stored in:

```text
evidence/runs/<UTC>-cloud-check/
├── timeline.jsonl
└── result.json
```

## If the camera has no WAN in SETUP

That is an expected possibility.

A useful result can be:

```text
TPAP transport succeeds
checkFirmwareVersionByCloud method exists
application-level error returned
upgrade_info remains empty
```

That distinguishes a valid API method with unavailable cloud connectivity from
an unsupported method or a broken encrypted session.

## Cached-only mode

To inspect existing/cached metadata without asking the camera to contact the
cloud:

```powershell
python .\v5patchlab.py cloud-check `
  --no-trigger `
  --poll-seconds 0
```

## If an exact URL appears

The result will expose:

```text
download_tplinkcloud_urls
```

Use the existing host-side downloader:

```powershell
python .\v5patchlab.py firmware-download-url `
  --url "<exact URL from result.json>" `
  --out .\firmware\c200v5-current.bin
```

This downloads the package to the PC. It does not ask the camera to install it.

## Deliberately absent

v1.0.4 never sends:

```text
cloud_config.fw_download
startFirmwareUpgrade
firmware install
downgrade
flash
reboot
```

The code contains no path that invokes those camera operations.
