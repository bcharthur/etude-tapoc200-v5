# V5PatchLab v1.0.6 — phone hotspot onboarding

Away from the home LAN, `192.168.1.79` is expected to be unreachable.

Instead, this version lets the scoped camera join a phone hotspot directly
through its local onboarding API.

## iPhone

Enable:

```text
Settings → Personal Hotspot
Allow Others to Join = ON
Maximize Compatibility = ON
```

Keep the hotspot enabled.

## 1. While Windows is still on Tapo_Cam_3ADA

```powershell
python .\v5patchlab.py hotspot-scan
```

Confirm `iPhone Arthur` appears.

## 2. Connect the camera

```powershell
python .\v5patchlab.py hotspot-connect `
  --ssid "iPhone Arthur" `
  --arm
```

The hotspot password is prompted securely.

The command uses:

```text
scanApList
→ reset-specific onboarding RSA public key
→ RSA PKCS#1 v1.5 encrypted hotspot password
→ connectAp
```

Password and RSA ciphertext are not stored in evidence.

`Tapo_Cam_3ADA` disappearing after success is expected.

## 3. Join the same hotspot from the PC

Manually connect Windows to `iPhone Arthur`, then:

```powershell
python .\v5patchlab.py hotspot-find
```

The tool scans only the active private Wi-Fi subnet, capped at 256 addresses,
and accepts only the already scoped camera MAC.

## 4. Re-run the firmware check with WAN

```powershell
python .\v5patchlab.py hotspot-cloud-check `
  --poll-seconds 20 `
  --interval 2
```

If the camera remains `pake:[0]`, it reuses the MAC-derived TPAP bootstrap and
runs the same firmware metadata calls as before.

It does not perform firmware installation, downgrade, flash, reboot, or account
binding.

## Most interesting comparison

```text
Tapo_Cam setup AP:
checkFirmwareVersionByCloud = -1

Phone hotspot / Internet:
checkFirmwareVersionByCloud = 0
upgrade_info = populated
```

If that happens, the lack of WAN explains the prior result and we may recover
the exact OTA URL without binding the camera to a Tapo account.
