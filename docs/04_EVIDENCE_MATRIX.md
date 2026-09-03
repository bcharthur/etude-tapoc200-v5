# Evidence matrix

| Finding | Status | Threat model | Why it matters | Missing proof |
|---|---|---|---|---|
| SETUP open `Tapo_Cam_*` SoftAP | CONFIRMED | post-pivot | exposes local provisioning network | S1 trigger into this state |
| SETUP TPAP `pake:[0]` MAC-derived bootstrap | CONFIRMED | S1 chain tail / S3 | privileged management without user account once SETUP is reachable | force SETUP from NORMAL by RF |
| SETUP Streamd historical default-key video disclosure | CONFIRMED | S1 chain tail | impact after provisioning pivot | force SETUP from NORMAL by RF |
| NORMAL bound TPAP management auth profile | CONFIRMED | S3 | implementation knowledge / patch research | not radio-only |
| ONVIF transplant crash | NOT REPRODUCED | S2/S3 | historical adjacent bug family | no causal V5 1.4.6 crash |
| C200 V5 1.4.2 public firmware acquired/decrypted | CONFIRMED | S3 | vulnerable-side implementation reference | exact 1.4.6 binary still needed for patch diff |
| `main` recovered from SquashFS | CONFIRMED | S3 | contains major application protocols/state logic | map radio/recovery handlers |
| `spake2p_MacVerify` nonzero normalization anomaly | CONFIRMED STATIC | S3 | candidate auth-validation flaw | return semantics + network reachability + 1.4.6 diff |
| 117-byte private-decrypt boundary/off-by-one candidate | STRONG HYPOTHESIS | S3 | candidate credential memory bug | exact caller/reachability + 1.4.6 diff |
| `onboarding_phy_link_status_change_handle` present in `main` | CONFIRMED STATIC | S1 | explicit junction between physical link status and onboarding logic | branch conditions/callers + dynamic proof |
| Re-onboarding / SoftAP state controls (`is_reonboarding`, `set_exit_softap_fast_flag`, `stop_exit_softap`) | CONFIRMED STATIC | S1 | shows provisioning fallback is a first-class state | prove RF-only transition from NORMAL |
| `/tmp/recovery_mode` + `DO NOT WRITE CONFIG` | CONFIRMED STATIC | S1/S3 | recovery is distinct from factory reset and should be classified separately | map entry conditions |
| Rootfs WPS/DPP/P2P raw-string hits in media/assets | LOW-CONFIDENCE / NOISE | none | demonstrates scanner false positives | require executable/config/call-flow corroboration |
| Radio-only NORMAL -> factory/provisioning | NOT YET DEMONSTRATED | **S1 primary** | completes target scenario | RF trigger and repeatability |
