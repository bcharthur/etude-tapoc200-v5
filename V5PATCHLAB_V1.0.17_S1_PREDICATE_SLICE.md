# V5PatchLab v1.0.17 — S1 predicate slice

Adds `s1-predicate-slice` and `scripts/export-s1-link-predicate.ps1`.

The command focuses on the newly recovered direct control-flow bridge from
`onboarding_phy_link_status_change_handle` to `wlan_manager_onboarding_start`.
It exports branch windows and nearby static evidence needed to determine the
exact runtime condition before any RF injection test is designed.

Also fixes misleading v1.0.16 summary wording: unresolved direct call sites are
now reported as call sites instead of being described as named direct callers.
