# V5PatchLab v1.0.15 — research documentation + S1 refocus

This release does not add a new network exploit path. It formalizes the research evidence and refocuses the next analysis on the original S1 goal: a radio-only NORMAL -> factory/provisioning transition.

New:

- `docs/` research journal, threat models, evidence matrix and S1 plan;
- `s1-static-map` command to index reset/provisioning/Wi-Fi/P2P/WPS/driver strings and symbols in `main`, optionally the extracted rootfs and approximate MIPS xrefs;
- `scripts/export-current-static-evidence.ps1` to preserve the reverse-engineering milestone;
- `scripts/run-s1-static-map.ps1` convenience wrapper.

Example:

```powershell
python .\v5patchlab.py s1-static-map `
  .\analysis\c200v5-142\main-1.4.2 `
  --rootfs <path-to-squashfs-root> `
  --xrefs `
  --out .\analysis\s1-static-map
```
## First real-device S1 map result

The first run against the extracted 1.4.2 rootfs identified the key static junction `onboarding_phy_link_status_change_handle` alongside the WLAN disconnect/reconnect manager and explicit re-onboarding/SoftAP state controls. See `docs/06_S1_STATIC_MAP_142_RESULTS.md`.

This result **does not demonstrate** a radio-only reset. It narrows the next P0 reverse-engineering target to the link-status -> onboarding policy branch and explicitly classifies raw WPS/DPP/P2P hits in media files as scanner noise unless corroborated.

## Superseded next-step tooling

v1.0.16 adds an automated `s1-controlflow` pass and passive SoftAP observer. See `V5PATCHLAB_V1.0.16_S1_CONTROLFLOW.md`.
