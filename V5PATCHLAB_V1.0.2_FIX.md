# V5PatchLab v1.0.2

## Fixed Ubuntu Noble bootstrap

`awscli` is no longer part of the apt transaction. The previous script aborted
before installing the external binwalk extractors because Ubuntu Noble in the
tested WSL image had no `awscli` apt candidate.

The new setup installs:

```text
jefferson
ubi-reader
```

with `pipx`, then checks:

```text
jefferson
ubireader_extract_files
```

before rerunning upstream `extract_keys.sh`.

## Bucket listing is now optional

The public TP-Link object bucket was historically listable, but the tested
AWS path-style list request now returns HTTP 403. v1.0.2 no longer treats that
as a fatal ParseError.

Use:

```powershell
python .\v5patchlab.py official-releases
```

to verify the official C200 V5 release line from TP-Link's support page.

## New scoped camera metadata query

While connected to the exact setup SSID:

```text
Tapo_Cam_3ADA
```

run:

```powershell
python .\v5patchlab.py camera-fw
```

This reuses the already-proven C200 V5 `pake:[0]` TPAP bootstrap and sends only:

```text
get_device_info
component_nego
get_latest_fw
get_fw_download_state
```

It does not start an update, downgrade, firmware download, reboot or flash.

If an exact `download.tplinkcloud.com/firmware/...` URL appears, it is surfaced
in `urls_found`.

Then:

```powershell
python .\v5patchlab.py firmware-download-url `
  --url "<exact URL>" `
  --out .\firmware\current.bin
```

For the historical 1.4.4 package, do not brute-force or guess the timestamp
suffix. We need an exact historical OTA URL/capture/indexed source.

## Correct shell context

These are Ubuntu commands, not PowerShell commands:

```bash
cd ~/tp-link-decrypt
command -v jefferson
command -v ubireader_extract_files
find ...
tail ...
```

Enter Ubuntu first with:

```powershell
wsl -d Ubuntu
```
