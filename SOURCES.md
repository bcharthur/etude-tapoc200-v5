# Public references used to design V5PatchLab

## TP-Link C200 V5 release history

Current public release line around the lab target:

```text
1.3.5 Build 260228
1.4.4 Build 260527
1.4.6 Build 260709
```

The lab camera has empirically reported:

```text
1.4.6 Build 260709 Rel.27675n
```

## CVE-2026-15315

TP-Link/CVE record:
- C200 V5 affected below V5_1.4.6 Build 260709 Rel.27675n
- improper authentication in login authentication verification
- weakness in challenge parameter validation
- administrative session tokens / privileged management actions

Canonical CVE repository:
https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/15xxx/CVE-2026-15315.json

## CVE-2026-15316

TP-Link/CVE record:
- C200 V5 affected below V5_1.4.6 Build 260709 Rel.27675n
- configuration service processes encrypted credential data
- oversized ciphertext input
- insufficient input validation / exception handling
- crash/restart and temporary management DoS

Canonical CVE repository:
https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/15xxx/CVE-2026-15316.json

## tp-link-decrypt

https://github.com/robbins/tp-link-decrypt

The project's README documents:
- `extract_keys.sh`
- `make`
- `bin/tp-link-decrypt <firmware>`
- keys derived from TP-Link-published GPL materials

Its current C program writes the decrypted image to:

```text
<input>.dec
```

## Evilsocket C200 reverse engineering

https://www.evilsocket.net/2025/12/18/TP-Link-Tapo-C200-Hardcoded-Keys-Buffer-Overflows-and-Privacy-in-the-Era-of-AI-Assisted-Reverse-Engineering/

The research workflow:
- lists/downloads Tapo firmware from the public `download.tplinkcloud.com` S3 bucket
- uses `tp-link-decrypt`
- uses `binwalk -e`
- then reverses extracted userspace binaries

That article targeted C200 V3. V5PatchLab uses the workflow as an acquisition
technique but does not assume the V3 vulnerabilities or binary layout are the
same on V5.


## Camera firmware cloud-check API

Public `pytapo` camera implementation uses a camera `multipleRequest` flow that
includes:

```text
checkFirmwareVersionByCloud
  cloud_config.check_fw_version = "null"

getCloudConfig
  cloud_config.name = ["upgrade_info"]
```

Reference:
https://github.com/JurajNyiri/pytapo/blob/main/pytapo/__init__.py

The same implementation uses a distinct write/action path:

```text
method = "do"
cloud_config.fw_download = "null"
```

to start a firmware upgrade. V5PatchLab v1.0.4 intentionally does not send or
expose that camera operation.


## Normal Camera Account authentication

PyTapo documents local camera authentication using the Camera Account created
in Tapo App -> Advanced Settings -> Camera Account:

https://github.com/JurajNyiri/pytapo/blob/main/README.md

Its camera firmware availability workflow uses:

```text
checkFirmwareVersionByCloud
getCloudConfig(upgrade_info)
```

and keeps the actual firmware-start action separate.


## Bound TPAP authentication

Current ioBroker.tapo TPAP implementation documents/implements:

```text
pake:[0] → default_userpw
pake:[2]/[5] → userpw
```

and derives the management username hash from `admin` for this TPAP family.
It also implements common `extra_crypt` credential transformations used by
TP-Link devices.

Reference:
https://github.com/TA2k/ioBroker.tapo/blob/main/src/lib/utils/tpapCipher.ts


## V1.0.8 OTA hunt
Targets exact C200 V5 builds 260527/Rel.28339n and 260709/Rel.27675n using public support/archive/index metadata only; no arbitrary object-key brute force.


## V1.0.9 strict OTA object hunt

Added public 2026 source:

- `https://github.com/Ripthulhu/tp-link-tapo-firmware`
- `all_firmware.txt`
- `tapo_firmware.txt`
- `tapo_firmware_urls.txt`

The repo describes itself as a list of firmware files in TP-Link's public S3
bucket and was created/pushed 2026-06-23.

The strict parser requires `Tapo_C200v5` plus exact version/build/Rel and no
longer promotes unrelated pages merely because `1.4.4` or `1.4.6` occurs
nearby.

Wayback TLS now prefers certifi, supports an explicit CA bundle, and has an
explicit `--wayback-insecure` fallback limited to public CDX metadata.


## V1.0.10 cloud-account firmware metadata

Public references used for the request shape:

- `dimme/tapo-cli`
  - Tapo Android request signing / account login
  - `/api/v2/common/getDeviceListByPage`
  - `/api/v2/common/passthrough`
  - camera request includes:
    - `checkFirmwareVersionByCloud`
    - `getCloudConfig` for `upgrade_info`

- `JurajNyiri/pytapo`
  - camera multipleRequest with the same
    `checkFirmwareVersionByCloud` + `upgrade_info` pair.

- Public firmware/rootfs research exposes update helper logic that reads:
  `cloud_config.upgrade_info.download_url`.

V1.0.10 only targets the scoped camera owned by the user and never invokes the
firmware-install methods.


## V1.0.11 no-account branch

- TP-Link France support page confirms the C200(EU) V5 release sequence,
  including 1.4.4 Build 260527 and 1.4.6 Build 260709.
- Ripthulhu public bucket snapshot contains the exact C200 V5
  1.4.2 Build 260513 Rel.33069n object key.
- Existing project TPAP0 implementation is reused for SETUP-state local
  metadata reads; no Tapo account authentication is added to that path.
