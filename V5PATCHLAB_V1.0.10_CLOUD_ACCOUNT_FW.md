# V5PatchLab v1.0.10 — cloud-account firmware metadata probe

## What the v1.0.9 run proved

The public-object hunt reached a useful boundary:

- the 2026 public bucket snapshot contains a real C200 V5 object:
  `Tapo_C200v5_en_1.4.2_Build_260513_Rel.33069n_...bin`
- no exact 1.4.4/260527 or 1.4.6/260709 object appeared in that snapshot
- S3 bucket listing is denied (`403 AccessDenied`)
- the CDN virtual-host listing form returns no listable XML
- Wayback returned no 1.4.4 rows when queried successfully
- the 1.4.6 Wayback query intermittently returned `503`

So public object discovery should no longer be the primary branch.

## v1.0.10 fixes

1. The v1.0.9 source `tapo_firmware_urls.txt` did not exist.
   The real repository contains `tapo_firmware.csv`; v1.0.10 uses it.

2. Wayback now uses an exact `matchType=prefix` query such as:

```text
download.tplinkcloud.com/firmware/assigned/
Tapo_C200v5_en_1.4.6_Build_260709
```

instead of regex filters across the whole bucket namespace.

3. New command:

```text
cloud-account-fw
```

This uses the user's own Tapo account, locates exactly the scoped C200 V5 by
MAC, and asks that camera through the normal Tapo cloud passthrough for:

```text
getCloudConfig(upgrade_info)
getFirmwareUpdateStatus
```

With `--arm` it additionally sends:

```text
checkFirmwareVersionByCloud
```

and polls the two read methods.

It does **not** send:

```text
startFirmwareUpgrade
fw_download
upgrade
reboot
factoryReset
```

## Why this is higher-value now

Public Tapo client implementations use exactly this camera request pair:

```text
checkFirmwareVersionByCloud
getCloudConfig(upgrade_info)
```

Firmware-side research also shows `upgrade_info.download_url` is the field used
by update helpers once cloud metadata has been populated.

The user's current local bound TPAP path has already had authentication
friction, whereas the account cloud path already knows the device identity and
the camera is bound to that account.

## First run — cached metadata only

```powershell
python .\v5patchlab.py cloud-account-fw
```

The script prompts:

```text
Tapo account email:
Tapo account password:
```

The password and cloud token are never written to result.json.

If MFA is enabled, the script attempts the known public Tapo MFA flow and asks
for the verification code interactively.

## Second run — trigger one cloud firmware check

Only if the cached read works:

```powershell
python .\v5patchlab.py cloud-account-fw `
  --arm `
  --poll-seconds 20 `
  --interval 2
```

## Strong outcomes

### A. Exact URL recovered

Look for:

```json
"download_tplinkcloud_urls": [
  "https://download.tplinkcloud.com/firmware/..."
]
```

Then:

```powershell
python .\v5patchlab.py firmware-download-url `
  --url "<EXACT URL>" `
  --out .\firmware\c200v5.bin
```

### B. No URL, but fwId/hwId/oemId recovered

Those identifiers are preserved in:

```text
interpretation.device_fwId
interpretation.device_hwId
interpretation.device_oemId
```

They become the next metadata-correlation keys.

### C. Current 1.4.6 reports no update metadata

That is a valid result: the camera is already on the current firmware. At that
point the best acquisition route for the old 1.4.4 image becomes either:

- historical firmware metadata/index sources keyed by the C200 V5 identity, or
- a hardware flash dump / UART path.

## Environment-token mode

To avoid an interactive login when you already have a legitimate account
token, set both variables in the current shell:

```powershell
$env:TAPO_TOKEN = "<token>"
$env:TAPO_APP_SERVER_URL = "https://n-euw1-wap-gw.tplinkcloud.com"
python .\v5patchlab.py cloud-account-fw --arm
```

Do not paste the token into chat.
