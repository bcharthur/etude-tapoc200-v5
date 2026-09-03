# S1 Provisioning v0.6.2

## Fixes

1. Removes the misleading warning that a Wi-Fi adapter must be connected.
   A disconnected adapter can scan normally, as demonstrated by the 9 visible
   networks in the previous run.

2. Parses setup-network security metadata from Windows `netsh`:

```text
network_type
authentication
encryption
BSSID
signal
radio_type
band
channel
```

Therefore a detected `Tapo_Cam_*` can be classified directly as open/protected
from the Windows scan output.

## Before reset

```powershell
python .\s1lab.py wifi-diagnose
```

Expected:

```text
ready_for_setup_ssid_observation = true
network_count > 0
recommendations = []
```

## Controlled factory-reset experiment

Start:

```powershell
python .\s1lab.py watch-transition --seconds 240
```

While it is running, manually factory-reset your own camera.

For a Tapo pan/tilt camera, the official procedure is to expose the RESET
button by tilting the lens upward and hold RESET for at least 5 seconds until
the reset LED indication occurs.

Do not reconnect/reconfigure the camera until the watcher has had time to see
the setup SSID.

## Expected evidence

```text
first_target_down != null
first_tapo_setup_ssid_seen != null
```

The JSONL entries will contain the full `tapo_setup_networks` record, including
authentication/encryption when Windows reports it.

## After watcher

Manually connect Windows Wi-Fi to your own:

```text
Tapo_Cam_XXXX
```

Then:

```powershell
python .\s1lab.py setup-probe
```
