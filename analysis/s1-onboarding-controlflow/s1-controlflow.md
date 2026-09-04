# S1 onboarding control-flow — v1.0.16

## Objective

Recover the exact static junction from Wi-Fi link-state events into re-onboarding/SoftAP/reboot state logic before designing an RF trigger.

Main: `analysis\c200v5-142\main-1.4.2`
SHA-256: `3d5d7d8a35fdad2766848c6de2edd8fcb1db6f1392013d2d9556cb192cdfab37`

## Priority bridge candidates

- **11** `onboarding_phy_link_status_change_handle` — groups: link, onboarding; reasons: link/WLAN state, onboarding/re-onboarding, 2 direct caller(s)
- **11** `wlan_manager_onboarding_start` — groups: link, onboarding; reasons: link/WLAN state, onboarding/re-onboarding, 2 direct caller(s)
- **11** `wlan_manager_reboot_thread` — groups: link, onboarding, reboot; reasons: link/WLAN state, onboarding/re-onboarding, reboot
- **10** `wlan_manual_reconnect` — groups: link, onboarding; reasons: link/WLAN state, onboarding/re-onboarding, 1 direct caller(s)
- **8** `ffs_onboarding_stop` — groups: onboarding; reasons: onboarding/re-onboarding, 3 direct caller(s)
- **8** `onboarding_restart` — groups: onboarding; reasons: onboarding/re-onboarding, 4 direct caller(s)
- **8** `onboarding_set_start_flag` — groups: onboarding; reasons: onboarding/re-onboarding, 3 direct caller(s)
- **8** `set_exit_softap_fast_flag` — groups: softap; reasons: SoftAP, 3 direct caller(s)
- **8** `wlan_manager_reboot` — groups: link, reboot; reasons: link/WLAN state, reboot, 2 direct caller(s)
- **7** `disconnect_WiFi_ex` — groups: link; reasons: link/WLAN state, 4 direct caller(s)
- **6** `ffs_onboarding_start` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `get_cur_onboarding_mode` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `is_onboarding_finished` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `is_onboarding_started` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `is_reonboarding` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `set_onboarding_finished` — groups: onboarding; reasons: onboarding/re-onboarding, 1 direct caller(s)
- **6** `stop_exit_softap` — groups: softap; reasons: SoftAP, 1 direct caller(s)
- **5** `wlan_manager_init_reconnect_ctx` — groups: link; reasons: link/WLAN state, 1 direct caller(s)
- **5** `wlan_sta_disconnect` — groups: link; reasons: link/WLAN state, 1 direct caller(s)
- **4** `wlan_manager_sta_disconnect` — groups: link; reasons: link/WLAN state

## Target functions

### `onboarding_phy_link_status_change_handle` @ `0x005366a0` size=216
Direct callers: `0x00533dc8`, `0x00533e0c`
Direct callees: `onboarding_ctx_init`, `wlan_manager_ap_get_status`, `wlan_manager_monitor_get_status`, `wlan_manager_onboarding_start`

### `wlan_manager_onboarding_start` @ `0x0052d4f4` size=292
Direct callers: `onboarding_phy_link_status_change_handle`, `wlan_manager_start`
Direct callees: `onboarding_set_start_flag`, `wlan_is_fac_test_mode`, `wlan_manager_ap_get_config`, `wlan_manager_sta_get_config`, `wlan_manager_support_host_ap`

### `onboarding_restart` @ `0x00536778` size=108
Direct callers: `0x0052d018`, `0x0052d1c0`, `0x0052d46c`, `0x00536824`
Direct callees: `onboarding_ctx_init`, `onboarding_set_start_flag`, `onboarding_stop`

### `wlan_manager_init_reconnect_ctx` @ `0x0052bfcc` size=56
Direct callers: `0x00536814`

### `wlan_manual_reconnect` @ `0x00537588` size=104
Direct callers: `0x00533778`
Direct callees: `onboarding_execute_shell_cmd+0x254`, `onboarding_execute_shell_cmd+0x330`, `onboarding_execute_shell_cmd+0xdc`

### `wlan_manager_sta_disconnect` @ `0x0052ab94` size=80
Direct callers: none recovered (may be indirect/PIC).
Direct callees: `wlan_sta_disconnect`

### `wlan_sta_disconnect` @ `0x00531270` size=148
Direct callers: `wlan_manager_sta_disconnect`

### `disconnect_WiFi_ex` @ `0x0052fc10` size=24
Direct callers: `0x00530284`, `0x005302bc`, `0x0053479c`, `0x005354a0`

### `is_reonboarding` @ `0x00536020` size=24
Direct callers: `0x005304d0`

### `get_cur_onboarding_mode` @ `0x00536068` size=24
Direct callers: `0x005305d4`

### `set_exit_softap_fast_flag` @ `0x00530970` size=24
Direct callers: `0x00530a9c`, `0x00531a74`, `init_wifi_op`

### `stop_exit_softap` @ `0x005308e4` size=140
Direct callers: `0x00535d10`

### `set_onboarding_finished` @ `0x00536dc4` size=128
Direct callers: `0x005305b4`

### `onboarding_set_start_flag` @ `0x00536080` size=28
Direct callers: `onboarding_restart`, `wlan_manager_onboarding_start`, `wlan_manager_start`

### `is_onboarding_finished` @ `0x00536d74` size=80
Direct callers: `0x0052cde0`

### `is_onboarding_started` @ `0x00536038` size=24
Direct callers: `0x0052e6e8`

### `ffs_onboarding_start` @ `0x00532480` size=68
Direct callers: `onboarding_module_start`

### `ffs_onboarding_stop` @ `0x005324c4` size=68
Direct callers: `0x005328dc`, `0x00535ea4`, `onboarding_stop`

### `wlan_manager_reboot` @ `0x0052d620` size=192
Direct callers: `0x0052dcc8`, `0x00534080`

### `wlan_manager_reboot_thread` @ `0x0052e4dc` size=424
Direct callers: none recovered (may be indirect/PIC).
Direct callees: `is_onboarding_ds_module_start`, `onboarding_ctx_init`, `onboarding_module_start`, `wlan_adapter_init`, `wlan_manager_start`, `wlan_manager_stop`

## Interpretation

`CONFIRMÉ` means a static direct call/string/branch is present in this ELF.

`HYPOTHÈSE` means the junction may convert RF/link failure into onboarding/SoftAP; static proximity alone is not enough.

`À TESTER` begins only after the controlling branch/timeout/reason-code is identified.

## Important limitation

A reboot or `/tmp/recovery_mode` is not a factory reset. The S1 success condition remains a repeatable radio-only transition into re-onboarding/SoftAP/unbound/factory state with no PSK, association, IP path or physical action.
