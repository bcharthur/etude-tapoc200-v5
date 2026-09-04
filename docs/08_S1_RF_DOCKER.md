# S1 RF Docker lab — Ethernet + internal RZ608

This environment packages the S1 802.11 tooling in Docker while leaving the
Linux host responsible for the Wi-Fi driver.

## Important boundary

Docker Desktop on Windows/WSL does **not** solve the current RZ608 limitation:
the Windows MediaTek driver only exposes `managed` mode and the internal PCIe
Wi-Fi device is not passed through by `usbipd`.

Use this Docker environment from a **native Linux boot** (installed Linux or an
Ubuntu/Kali live USB). Ethernet can remain the Internet/default route while the
internal RZ608 is dedicated to the RF lab.

Expected stack:

```text
Ethernet -> Linux host Internet/default route
RZ608    -> mt7921e/mac80211 -> Docker host network namespace -> mon0
```

The container is privileged and uses host networking because `iw` must create a
monitor virtual interface on the host PHY. Use only on the owned lab camera.

## Files

- `Dockerfile.rf`
- `docker-compose.rf.yml`
- `scripts/rf_container_entrypoint.sh`
- `scripts/s1_rf_trial.py`

The Python trial remains bounded to a maximum of three injected management
frames per run.

## 1. Boot Linux natively

After boot, verify Ethernet first:

```bash
ip route
ping -c 2 1.1.1.1
```

Then verify the RZ608:

```bash
lspci -nnk | grep -A3 -Ei 'network controller|wireless'
iw dev
```

For the RZ608 the expected kernel driver is normally `mt7921e`.

## 2. Build the RF container

From the repository:

```bash
docker compose -f docker-compose.rf.yml build
```

## 3. Probe only

This does not inject anything:

```bash
docker compose -f docker-compose.rf.yml run --rm rf probe
```

Expected useful output:

```text
Wi-Fi interface: <name>
Driver         : mt7921e
PHY            : phy0
Supported interface modes:
    * managed
    * monitor
...
monitor mode advertised: YES
```

Stop here if `monitor` is absent.

## 4. Passive observation

Determine the camera AP's 2.4 GHz channel, then run for example:

```bash
docker compose -f docker-compose.rf.yml run --rm rf \
  observe --channel 6 --observe-seconds 60
```

The entrypoint creates `mon0`, pins it to the requested channel, starts Scapy,
and removes `mon0` when the container exits.

Evidence is written on the host under:

```text
evidence/runs/<timestamp>-s1-rf-docker-observe/
```

## 5. Bounded management-frame trial

Only after the passive baseline and after confirming the legitimate AP BSSID:

```bash
docker compose -f docker-compose.rf.yml run --rm rf \
  deauth \
  --channel 6 \
  --ap-bssid aa:bb:cc:dd:ee:ff \
  --count 1 \
  --observe-seconds 60
```

Or a separate disassociation trial:

```bash
docker compose -f docker-compose.rf.yml run --rm rf \
  disassoc \
  --channel 6 \
  --ap-bssid aa:bb:cc:dd:ee:ff \
  --count 1 \
  --observe-seconds 60
```

Do not turn these into flood tests. The experiment is looking for a reproducible
state transition, not packet loss.

## Success signal

Inspect `summary.json`. The interesting state-machine signal is:

```json
"softap_seen": true
```

That means a `Tapo_Cam_*` beacon was observed and is a candidate
SoftAP/re-onboarding transition. Temporary Wi-Fi loss or a reboot alone does not
count as a factory/provisioning pivot.
