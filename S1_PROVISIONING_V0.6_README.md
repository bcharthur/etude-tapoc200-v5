# Tapo C200 V5 — S1 Provisioning Observer v0.6

## Goal

Move from:

```text
S2: already on victim LAN, no credentials
```

toward:

```text
S1: nearby RF attacker, no home Wi-Fi PSK, no Tapo account
```

This patch does NOT create the transition.

It only observes the camera while the owner manually changes state.

It never:
- presses/automates reset;
- removes the camera from Tapo;
- changes Wi-Fi settings;
- connects Windows to a Wi-Fi network automatically;
- guesses setup IPs;
- sweeps a subnet.

## Important: factory reset is destructive

A factory reset removes the current configuration and requires pairing the
camera again.

Only perform one when you are ready to reconfigure your own device.

TP-Link documents that a reset camera enters setup mode and advertises a
temporary SSID of the form:

```text
Tapo_Cam_XXXX
```

The exact security/open-network behavior should be measured on the V5 rather
than assumed.

## 1. Wi-Fi scan

```powershell
python .\s1lab.py wifi-scan
```

Uses:

```text
netsh wlan show networks mode=bssid
```

It does not connect anywhere.

## 2. Current Windows network state

```powershell
python .\s1lab.py netstate
```

## 3. Observe a controlled transition

Start before a manual reset/reboot experiment:

```powershell
python .\s1lab.py watch-transition --seconds 180
```

Records:

```text
443 reachable?
554 reachable?
2020 reachable?
8800 reachable?
Tapo_Cam_* visible over RF?
```

Evidence:

```text
evidence\runs\<timestamp>\
├── s1-transition.jsonl
├── s1-transition-summary.json
└── manifest.json
```

The watcher performs no destructive action itself.

## 4. After manually connecting Windows to setup Wi-Fi

Only after Windows is actually connected to your own:

```text
Tapo_Cam_XXXX
```

run:

```powershell
python .\s1lab.py setup-probe
```

The tool refuses to probe unless the connected SSID begins with `Tapo_Cam_`.

It then:
1. reads the Wi-Fi IPv4 configuration;
2. uses only the DHCP/default-gateway address as camera candidate;
3. probes 443/554/2020/8800;
4. if 443 is open, sends only `login/discover`.

No subnet scan or password is used.

## Questions this phase should answer

```text
NORMAL
  ↓ reset
when does LAN IP disappear?

When does Tapo_Cam_XXXX appear?

Is setup Wi-Fi open or protected?

What address does the camera use as setup AP/gateway?

Which services are reachable in SETUP state?

Does HTTPS/443 expose TPAP in SETUP state?

Does TDP/20002 exist in SETUP state?

Does factory_default become true?

Does the persistent TDP AES material survive reset?
```

The last two require a follow-up patch after setup topology is empirically known.
