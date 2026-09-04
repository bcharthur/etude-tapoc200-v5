# S1 RF runner from Windows + WSL

## Goal

Run bounded 802.11 management-frame trials against the owned C200 V5 while the
host operating system is Windows.

Native Windows raw IP sockets are not the right layer for this test. The runner
therefore uses:

```text
PowerShell / Windows
        |
        +-- usbipd-win -> dedicated USB Wi-Fi adapter
        |
        +-- WSL2 Linux
                |
                +-- iw / monitor mode
                +-- Scapy / Radiotap + 802.11
                +-- evidence/runs/<timestamp>-s1-rf-*/
```

The injector intentionally caps a trial at **3 frames maximum**. The objective is
state-machine attribution, not traffic flooding.

## Important hardware limitation

`usbipd-win` forwards USB devices. A laptop's internal PCIe Wi-Fi card normally
will not appear here. Prefer a dedicated USB Wi-Fi adapter whose Linux driver
supports monitor mode and packet injection.

The decisive check is not the adapter brand: after USB passthrough, `iw dev` and
`iw phy` must expose the interface/PHY and the driver must accept monitor mode.

## Prerequisites

- WSL2 distribution installed (examples below use `Ubuntu`);
- `usbipd-win` installed on Windows;
- dedicated USB Wi-Fi adapter;
- repository checked out on Windows.

Install `usbipd-win` if needed:

```powershell
winget install --interactive --exact dorssel.usbipd-win
```

## 1. Find the USB BUSID

```powershell
.\scripts\run-s1-rf-windows.ps1 -Mode list-usb
```

Example BUSID: `4-4`.

The first `usbipd bind` for a device requires an Administrator PowerShell. The
runner can perform it when launched elevated, or it will print the exact command
to run. `usbipd attach --wsl` is then used to expose the adapter to WSL.

## 2. Probe WSL + install Linux dependencies

```powershell
.\scripts\run-s1-rf-windows.ps1 `
  -Mode probe `
  -Distro Ubuntu `
  -BusId 4-4 `
  -InstallDeps
```

This installs/validates:

- `iw`;
- `usbutils` (`lsusb`);
- `python3-scapy`.

The probe prints `lsusb`, `iw dev` and `iw phy`. Record the actual Wi-Fi interface
name; in the examples below it is `wlan0`.

If the USB device appears in `lsusb` but no wireless PHY/interface appears in
`iw`, the current WSL kernel likely lacks the adapter's Linux driver. That must be
resolved before trying injection.

## 3. Passive baseline first

Set the adapter to the legitimate AP channel and observe without injecting:

```powershell
.\scripts\run-s1-rf-windows.ps1 `
  -Mode observe `
  -Distro Ubuntu `
  -BusId 4-4 `
  -Interface wlan0 `
  -Channel 6 `
  -ObserveSeconds 60
```

Default camera MAC:

```text
dc:62:79:8b:3a:da
```

Override it with `-CameraMac` if needed.

For a strict S1 run, do not use the injected adapter to associate with the
protected WLAN and do not give WSL the WLAN PSK. Ideally the Windows host itself
uses another path (Ethernet/another network) during the radio-only trial so the
evidence clearly separates monitoring/injection from normal WLAN access.

## 4. One-frame deauthentication trial

After obtaining the AP BSSID and channel from passive/reproducible lab evidence:

```powershell
.\scripts\run-s1-rf-windows.ps1 `
  -Mode deauth `
  -Distro Ubuntu `
  -BusId 4-4 `
  -Interface wlan0 `
  -Channel 6 `
  -ApBssid aa:bb:cc:dd:ee:ff `
  -Count 1 `
  -ObserveSeconds 60
```

`-Count` is constrained to `1..3` by both PowerShell and Python.

A separate disassociation trial is available:

```powershell
.\scripts\run-s1-rf-windows.ps1 `
  -Mode disassoc `
  -BusId 4-4 `
  -Interface wlan0 `
  -Channel 6 `
  -ApBssid aa:bb:cc:dd:ee:ff `
  -Count 1 `
  -ObserveSeconds 60
```

Add `-RestoreManaged` if the dedicated adapter should be returned to managed mode
after the trial.

## Evidence

Each run creates:

```text
evidence/runs/<timestamp>-s1-rf-<mode>/
├── summary.json
└── radio-evidence.pcap   # only when relevant frames were captured
```

`summary.json` records:

- exact action/count;
- timestamps;
- target camera MAC and AP BSSID;
- relevant camera-frame count;
- any observed `Tapo_Cam_*` beacon;
- `softap_seen` boolean.

The PCAP deliberately keeps only frames involving the camera plus
`Tapo_Cam_*` beacons, reducing unrelated traffic retained by the lab.

## Interpretation

A lost ping is not the success condition. Classify results using the existing S1
state ladder:

```text
0 none
1 disconnect
2 reconnect
3 reboot
4 recovery
5 SoftAP/re-onboarding
6 unbound
7 verified factory reset
```

The high-value signal for the current hypothesis is `softap_seen=true`, followed
by independent confirmation that the device actually entered provisioning or
re-onboarding state.

If a correctly injected deauthentication/disassociation has no effect, verify
channel/BSSID/injection support and then check whether PMF/802.11w is protecting
the station's management frames before drawing conclusions about the onboarding
state machine.
