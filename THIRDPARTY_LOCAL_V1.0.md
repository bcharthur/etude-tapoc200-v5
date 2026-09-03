# Tapo C200 V5 — enable RTSP/ONVIF locally without the app toggle

A public cloudless-onboarding implementation shows that the local camera API
configures the RTSP/ONVIF account with:

```text
setAccountEnabled
changeThirdAccount
secname = third_account
```

This patch implements only that state change for the scoped C200 V5.

## Safety / scope gate

It refuses to run unless Windows is connected to the exact setup SSID derived
from the target MAC in `config/scope.json`.

For the current unit this resolves to:

```text
Tapo_Cam_3ADA
```

It targets only the Wi-Fi DHCP default gateway, never a subnet scan.

## Usage

After a factory reset, connect manually to the camera setup SSID.

Probe:

```powershell
python .\thirdparty.py probe
```

Enable:

```powershell
python .\thirdparty.py enable --username tapolab --arm
```

The RTSP/ONVIF password is requested interactively and is not put into
PowerShell history or written to disk.

## Important

This patch does NOT yet configure the home Wi-Fi.

It proves/removes the dependency on the native app's "Third-Party
Compatibility / Camera Account" UI by invoking the local user-management
methods directly.

After the command succeeds, either:
- continue normal pairing and test whether the flag survives; or
- extend the lab with `scanApList/connectAp` to do the entire onboarding
  locally without the app.

If native app pairing overwrites the third-account state, the second option is
the correct next step.
