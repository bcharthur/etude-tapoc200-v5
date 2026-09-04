# S1 — passive RF state observer

This helper exists so the next active RF experiment can be measured without conflating a simple disconnect/reboot with a provisioning transition.

## Start the observer

```powershell
.\scripts\observe-s1-softap.ps1 -Seconds 300 -Interval 2
```

It records appearances of SSIDs beginning with `Tapo_Cam_` using Windows `netsh wlan show networks mode=bssid`.

Evidence is written to:

```text
evidence/s1-rf-observe/
├── softap-observation.jsonl
└── softap-observation-summary.json
```

## Interpretation

- no `Tapo_Cam_*`: no observed SoftAP transition;
- `Tapo_Cam_*` appears: provisioning/SoftAP visibility is observed;
- this still does **not** prove factory reset;
- factory reset additionally requires loss of prior binding/configuration or equivalent device-state evidence.

This observer does not inject any 802.11 frames. Its job is only to preserve timestamps and state evidence while a separate, bounded experiment is run.
