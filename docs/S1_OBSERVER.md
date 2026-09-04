# S1 synchronized observer

This overlay adds a passive, timestamped observation harness without changing the existing `memorylab.py` CLI.

## What it records

- TCP 443/554/8800 transitions and samples.
- ARP/neighbor changes for the scoped camera IP.
- Existing `memstate.network.snapshot()` before, periodically, and after the experiment.
- Windows `netsh wlan show networks mode=bssid` scans, including new SSIDs/BSSIDs.
- Optional RTSP liveness/frame heartbeat through OpenCV.
- Optional read-only Tapo API health checks through `pytapo` (`getBasicInfo`/`getDeviceInfo` only).
- Optional Wireshark `dumpcap`/`tshark` PCAP capture when an interface is explicitly selected.
- Operator markers from a second terminal (`AP_OFF`, `AP_ON`, notes, etc.).

It **does not read raw camera RAM**. It correlates external evidence with the state snapshots already available in this project.

## Install

Extract the ZIP at the repository root.

Optional features:

```powershell
python -m pip install -r .\requirements-observer.txt
```

Copy credentials only if you need RTSP/Tapo probes:

```powershell
Copy-Item .\.env.observer.example .\.env.observer
notepad .\.env.observer
```

Never commit `.env.observer`.

## Preflight

```powershell
python .\observerlab.py preflight
```

The output lists Wireshark capture interfaces when `dumpcap`/`tshark` is installed.

## Start an observation

Base observation, no PCAP interface required:

```powershell
python .\observerlab.py observe --label S1-WLAN-LOSS --seconds 180
```

With PCAP after choosing an interface from preflight:

```powershell
python .\observerlab.py observe --label S1-WLAN-LOSS --seconds 180 --pcap-interface 4
```

Run without RTSP/Tapo if Camera Account is disabled:

```powershell
python .\observerlab.py observe --label S1-WLAN-LOSS --seconds 180 --no-rtsp --no-tapo
```

## Add operator markers from a second PowerShell

```powershell
python .\observerlab.py mark AP_OFF
python .\observerlab.py mark AP_ON
python .\observerlab.py mark "LED changed to amber" --kind NOTE
```

## Evidence

Each run is stored under `evidence/runs/<timestamp>-observe-<label>/` and contains:

- `experiment.json`
- `timeline.jsonl`
- `markers.jsonl`
- `merged-timeline.jsonl`
- `network.jsonl`
- `arp.jsonl`
- `wifi.jsonl`
- `rtsp.jsonl` (if enabled)
- `tapo.jsonl` (if enabled)
- `capture.pcapng` (if enabled)
- `state-before.json`
- `state-after.json`
- `state-samples/*.json`
- `summary.json`
- `manifest.json`

## S1 test discipline

The first experiment should only cause a legitimate AP/WLAN loss on the owner's lab camera (for example disabling the lab AP temporarily). Do not start active 802.11 injection yet. First establish whether an ordinary WLAN loss changes the camera's externally observable state and/or exposes a provisioning-like SSID.
