# V5PatchLab v1.0.16 — S1 onboarding control-flow

This release keeps the project focused on the original black-box radio objective.

## New

- `s1-controlflow`: direct-call/caller/branch/string reconstruction around the 1.4.2 WLAN/onboarding junction.
- ranked bridge candidates so `onboarding_phy_link_status_change_handle` and its neighbors can be reviewed first.
- explicit retention of unresolved PIC `jalr` calls instead of inventing targets.
- `scripts/export-s1-onboarding-controlflow.ps1`.
- `s1-observe-softap`: passive Windows observer for `Tapo_Cam_*` transitions during later RF experiments.
- two new runbooks in `docs/`.

## Immediate command

```powershell
.\scripts\export-s1-onboarding-controlflow.ps1
```

Paste back `analysis\s1-onboarding-controlflow\s1-controlflow.md` plus the JSON for `onboarding_phy_link_status_change_handle`; that should be enough to reconstruct the next branch conditions without another huge raw firmware dump.
