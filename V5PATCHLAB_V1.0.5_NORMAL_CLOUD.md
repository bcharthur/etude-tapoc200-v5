# V5PatchLab v1.0.5 — NORMAL/LAN firmware cloud-check

## Why this is the next experiment

The SETUP run established:

```text
TPAP transport                        OK
getCloudConfig(upgrade_info)          OK
checkFirmwareVersionByCloud transport OK
application result                    -1
upgrade_info                           type=0, location=0
20 s polling                           no metadata change
firmware URL                           none
```

That is consistent with a valid local API in an environment where the camera
has no vendor-cloud/WAN path.

The next clean A/B test is therefore:

```text
same camera
same firmware
same firmware-check API
SETUP/no-WAN     vs     NORMAL/home-Wi-Fi
```

## Step 1 — return camera to NORMAL

Pair the camera normally with the Tapo application onto the home Wi-Fi.

Use the same scoped physical camera. Do not downgrade it.

The project scope currently expects its normal address to be:

```text
192.168.1.79
```

After pairing:

```powershell
python .\v5patchlab.py normal-ready
```

A good result is:

```text
443 = reachable
discovery MAC = DC62798B3ADA
pake = [2] or another bound-state value
noc = 1
```

## Step 2 — install current dependencies

```powershell
pip install -r .\requirements-v5patchlab.txt
```

v1.0.5 adds `pytapo`, whose documented primary authentication mechanism is the
Camera Account configured under Tapo Camera Advanced Settings.

## Step 3 — run NORMAL cloud metadata check

If the Camera Account username you created is `tapolab`:

```powershell
python .\v5patchlab.py normal-cloud-check `
  --user tapolab `
  --poll-seconds 20 `
  --interval 2
```

The password is requested with:

```text
getpass
```

It is not accepted as a command-line argument and is not stored in:

```text
result.json
timeline.jsonl
stdout
shell history
```

## Operations performed

After local Camera Account authentication:

```text
getBasicInfo
getFirmwareUpdateStatus
getCloudConfig(upgrade_info)

checkFirmwareVersionByCloud

poll:
  getCloudConfig(upgrade_info)
  getFirmwareUpdateStatus
```

The command deliberately does NOT call:

```text
startFirmwareUpgrade
fw_download
upgrade
downgrade
flash
reboot
```

## Expected high-value outcomes

### A. Exact firmware URL appears

Example shape:

```text
download_tplinkcloud_urls:
  - https://download.tplinkcloud.com/firmware/...
```

Then download it to the PC with:

```powershell
python .\v5patchlab.py firmware-download-url `
  --url "<EXACT URL>" `
  --out .\firmware\c200v5-1.4.6.bin
```

### B. `upgrade_info` becomes populated but contains no URL

Fields such as:

```text
version
release/build
filename
hash
size
location
type
```

still give us enough information to hunt the exact OTA object.

### C. Cloud check still returns failure in NORMAL

Then the next branch is not more polling. We inspect:

```text
cloud registration/binding state
mobile_access
cloud_config fields
DNS/time state
```

or query the Tapo cloud side rather than the camera.

## Evidence

```text
evidence/runs/<UTC>-normal-cloud-check/
├── timeline.jsonl
└── result.json
```

Only the SHA-256 of the supplied Camera Account username is persisted.
The password is never persisted.
