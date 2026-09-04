# V5PatchLab v1.0.3 — camera multipleRequest fix

## What the latest run proved

The environment is now ready:

```text
jefferson               true
ubireader_extract_files true
tp_link_decrypt.exists  true
```

The upstream key extractor also reported that the extracted RSA keys match the
expected data, then built `bin/tp-link-decrypt`.

The official TP-Link C200 V5 release page returned:

```text
1.4.6 / 260709
1.4.4 / 260527
```

## Why `camera-fw` returned InvalidTag

v1.0.2 mixed two different Tapo application APIs.

It sent:

```json
{"method":"get_device_info","params":{}}
```

directly inside the encrypted TPAP session.

That shape is associated with the SMART/Kasa-style API used by plugs and other
devices. Tapo cameras use a different camera control schema and normally wrap
calls in:

```json
{
  "method": "multipleRequest",
  "params": {
    "requests": [
      {
        "method": "getDeviceInfo",
        "params": {
          "device_info": {
            "name": ["basic_info"]
          }
        }
      }
    ]
  }
}
```

This is also the same top-level `multipleRequest` transport envelope already
proven on the C200 V5 during the third-account experiment.

v1.0.3 therefore sends exactly ONE encrypted `multipleRequest` containing only
four read-only camera requests:

```text
getDeviceInfo
getFirmwareUpdateStatus
getFirmwareAutoUpgradeConfig
getClockStatus
```

No write/update/reboot method is sent.

## Run

Stay connected to:

```text
Tapo_Cam_3ADA
```

Then:

```powershell
python .\v5patchlab.py camera-fw
```

Important fields:

```text
transport.ok
labeled_responses.device_info
labeled_responses.firmware_update_status
urls_found
```

If `transport.ok=true`, the AES-CCM/session layer is confirmed for this camera
request shape even if one specific firmware method returns an application-level
error.

## About the previous 403

The command:

```powershell
--url "http://download.tplinkcloud.com/firmware/....bin"
```

contained a literal placeholder, not a real firmware object path. A 403 from
that URL says nothing about availability of the actual package.

v1.0.3 now refuses placeholder URLs before making an HTTP request.

## Important observation from tp-link-decrypt bootstrap output

The huge C210v1 ARM filesystem printed by binwalk is NOT the target C200 V5
firmware. It is one of the public firmware inputs used by `tp-link-decrypt` to
recover TP-Link package keys.

Do not feed that C210 tree into the C200 V5 patch diff.

Its presence does prove that the filesystem extractors are now functioning.
