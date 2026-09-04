# C200 V5 — ONVIF vulnerability-transplant lab v1.0

## Goal
Test whether the C200 V5 1.4.6 ONVIF implementation still shows a parser weakness related to **CVE-2025-8065**, without attempting code execution.

Two public descriptions are tested separately:

1. **TP-Link CNA/CVE record:** oversized XML namespace prefix copied into a fixed stack buffer.
2. **Evilsocket public C200 V3 PoC:** `CreateRules` containing a very large number of `SimpleItem` elements crashes the ONVIF parser.

The published affected C200 product is **V3**, not V5. A V5 result must therefore be reproduced empirically; do not infer vulnerability from family similarity.

## Guardrails
- only `config/scope.json`; no arbitrary target argument
- SETUP requires exact `Tapo_Cam_<MAC suffix>` SSID
- target MAC verified via HTTPS discovery
- TCP/2020 must already be reachable
- explicit `--arm`
- one testcase at a time
- 443/554/2020/8800 checked before/after each case
- stop immediately at first service/system failure
- recovery watch up to 60 seconds
- no shellcode, ROP, command execution, persistence, or 100k-element payload

## Recommended sequence
If you are still connected to `Tapo_Cam_3ADA` with `third_account` enabled:

```powershell
python .\onviflab.py probe --state setup
```

Then test the current vendor/CNA description first:

```powershell
python .\onviflab.py sweep `
  --state setup `
  --axis prefix `
  --profile conservative `
  --arm
```

Conservative prefix lengths:
`1 8 16 32 64 96 128 192 256 384 512 768 1024 1536 2048`

If all survive, optionally:

```powershell
python .\onviflab.py sweep --state setup --axis prefix --profile extended --arm
```

Extended stops at 8192 characters.

Only then test the researcher's element-count grammar:

```powershell
python .\onviflab.py sweep `
  --state setup `
  --axis elements `
  --profile conservative `
  --arm
```

Conservative stops at 2048 `SimpleItem` elements; extended at 16384. The public V3 PoC used 100,000, intentionally excluded here.

## Verdicts
- `ONVIF_STILL_REACHABLE`: no crash oracle at this boundary; not proof of memory safety.
- `ONVIF_SERVICE_DOWN_DEVICE_STILL_REACHABLE`: 2020 died while 443/8800 remain; high-value service/process crash candidate.
- `MULTI_SERVICE_DOWN_POSSIBLE_REBOOT_OR_SYSTEM_CRASH`: multiple major services disappeared; recovery watch distinguishes reboot/restart behavior.

Evidence is written under:
`evidence/runs/<UTC>-onvif-<axis>-<profile>/`
with `events.jsonl` and `summary.json`.

## Offline patch-diff seeds
If you later obtain extracted `main` binaries:

```powershell
python .\onviflab.py binary-index .\firmware\v3-main
python .\onviflab.py binary-index .\firmware\v5-main
python .\onviflab.py binary-compare .\firmware\v3-main .\firmware\v5-main
```

This only indexes ONVIF/CreateRules/SimpleItem/string anchors for Ghidra navigation. It is not a full binary diff engine.

## Decision rule
A reproducible boundary like `prefix=384 survives; prefix=512 kills :2020` justifies moving immediately to V5 firmware parser reverse/patch-diff and UART/GDB acquisition. If both extended sweeps survive, classify the known V3 grammars as **not reproduced on V5 1.4.6** and prioritize V5-specific RTSP/HTTPS patch-diff instead of increasing payloads indefinitely.
