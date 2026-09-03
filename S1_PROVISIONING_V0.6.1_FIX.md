# S1 Provisioning v0.6.1 — Windows Wi-Fi preflight fix

The v0.6 output:

```text
network_count = 0
Wi-Fi state   = disconnected
Wi-Fi IPv4    = 169.254.x.x
```

is ambiguous and must NOT be used to conclude that no nearby AP exists.

## New diagnostic

```powershell
python .\s1lab.py wifi-diagnose
```

A healthy observer should report:

```text
ready_for_setup_ssid_observation = true
network_count > 0
```

The PC may remain connected to the LAN through Ethernet. The Wi-Fi adapter
only needs to be enabled and able to scan.

If false, verify:
- Wi-Fi radio enabled;
- WLAN AutoConfig running;
- Windows Privacy & security > Location allows WLAN scan visibility.

## Watcher behavior

`watch-transition` now refuses to start if Wi-Fi observation is unreliable:

```powershell
python .\s1lab.py watch-transition --seconds 240
```

Optional LAN-only override:

```powershell
python .\s1lab.py watch-transition --seconds 240 --allow-unreliable-wifi
```

A LAN-only run cannot be used to claim that `Tapo_Cam_*` was absent.

## Important interpretation of the previous run

The previous 180-second run had:

```text
first_target_down = null
first_tapo_setup_ssid_seen = null
```

Since the camera never disappeared from its normal LAN address, no
normal→setup transition was observed.

Do not run `setup-probe` until the PC has been manually connected to your
camera's own `Tapo_Cam_*` network.
