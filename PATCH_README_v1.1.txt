Tapo C200 S1 Observer patch v1.1.0
==================================

Overlay this ZIP at the root of etude-tapoc200-v5 AFTER v1.0.0.
It only replaces observer harness files added by v1.0; it does not touch the
original memorylab/memstate project code.

Changes:
- Adds Windows pktmon host-stack capture fallback when Npcap is unavailable.
- Adds `observerlab.py passive` non-disruptive deep-observation profile.
- Preflight now distinguishes Wireshark/Npcap from pktmon.
- Wireshark capture detects immediate startup failure instead of silently
  pretending a capture is active.
- Explicitly documents that host capture does not see ambient camera<->AP/cloud
  traffic unless the laptop is on-path.

Quick start (PowerShell AS ADMINISTRATOR for pktmon):
  python .\observerlab.py preflight
  python .\observerlab.py passive --label S1-PASSIVE --seconds 900 --capture-backend pktmon

No Internet/AP interruption is required. The profile only performs read-only
health/state probes and packet capture involving the laptop.

To observe the camera's own 802.11 management/association traffic without
interrupting it, use the Alfa adapter in passive monitor mode as a separate
capture source. Do not inject/deauth for this phase.
