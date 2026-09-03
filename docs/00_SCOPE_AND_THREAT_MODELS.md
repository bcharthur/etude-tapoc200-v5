# Tapo C200 V5 — scope, threat models and evidence rules

## Scope

This repository documents authorized research on a personally controlled TP-Link Tapo C200 V5 (EU). The goal is to understand the device from radio to userspace and to preserve reproducible evidence for each conclusion.

Current observed device firmware: `1.4.6 Build 260709 Rel.27675n`, hardware `5.0`.
Known public same-hardware baseline acquired for static analysis: `1.4.2 Build 260513 Rel.33069n`.

## Threat models

### S1 — black-box RF

Nearby attacker only. No Wi-Fi PSK, no Tapo account, no camera account, no IP reachability, no physical access. The attacker may monitor and inject 802.11 radio traffic in a controlled lab.

**Primary success condition:** force a camera that starts NORMAL/bound to enter factory/provisioning state using radio traffic only. A reboot or temporary disconnect is not sufficient.

### S2 — grey-box LAN

Same SSID/VLAN and IP reachability, but no camera credentials/account and no firmware knowledge.

### S3 — white-box

Same network reachability as S2, plus firmware/protocol implementation knowledge, still no user credentials during the test.

## Evidence labels

- **CONFIRMED** — directly reproduced or supported by exact static/dynamic evidence.
- **HYPOTHESIS** — technically plausible and supported by partial evidence, but not yet reproduced end-to-end.
- **TO TEST** — next experiment required to distinguish competing explanations.

## State model

`NORMAL -> REBOOT/RECOVERY/UNBOUND/FACTORY/WIFI-BACKUP -> PROVISIONING -> BOUND`

For S1, the missing link is the left side: a radio-only transition out of NORMAL. Existing SETUP/TPAP/Streamd findings are valuable for completing a chain **after** that pivot, but they do not by themselves satisfy S1.
