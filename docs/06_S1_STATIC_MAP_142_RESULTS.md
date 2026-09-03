# S1 static map — C200 V5 firmware 1.4.2 results

This note records the first `s1-static-map` result obtained against the extracted
C200 V5 `1.4.2 Build 260513 Rel.33069n` userspace.

The objective is not to claim a radio exploit from string presence. The purpose
of this pass is to identify the **junctions worth reversing next** for the S1
scenario:

`NORMAL/bound STA -> radio-only event -> provisioning / re-onboarding / factory state`

## CONFIRMED STATIC

### 1. Wi-Fi link handling and onboarding coexist in the same application

The recovered `main` contains explicit symbols/strings for both Wi-Fi state
management and onboarding state management, including:

- `wlan_sta_disconnect`
- `wlan_manager_sta_disconnect`
- `disconnect_WiFi_ex`
- `wlan_manual_reconnect`
- `wlan_manager_init_reconnect_ctx`
- `wlan_manager_reboot`
- `wlan_manager_reboot_thread`
- `wlan_manager_onboarding_start`
- `onboarding_restart`
- `onboarding_phy_link_status_change_handle`
- `is_reonboarding`
- `is_onboarding_started`
- `is_onboarding_finished`
- `set_onboarding_finished`
- `get_cur_onboarding_mode`
- `g_onboarding_mode`
- `set_exit_softap_fast_flag`
- `stop_exit_softap`
- `ffs_onboarding_start`
- `ffs_onboarding_stop`

This is materially stronger than generic `softap`/`disconnect` strings. In
particular, the name `onboarding_phy_link_status_change_handle` establishes that
**physical link-state changes are explicitly consumed by onboarding logic**.
It does not establish that an unauthenticated radio frame can force onboarding,
but it identifies the highest-value control-flow junction for the next reverse
engineering pass.

Known symbol addresses from the first report include:

- `wlan_sta_disconnect`: `0x531270`
- `wlan_manual_reconnect`: `0x537588`
- `ffsRaspbianConnectWithWpaSupplicant`: `0x5818d4`
- `esp32_driver_flag`: `0x7d1f20`

### 2. SoftAP / re-onboarding is a first-class state, separate from generic reboot

The binary contains explicit SoftAP exit state (`set_exit_softap_fast_flag`,
`stop_exit_softap`) and a dedicated `is_reonboarding` predicate. Therefore the
research must distinguish at least:

- ordinary reconnect;
- reboot with configuration intact;
- re-onboarding / SoftAP;
- unbound state;
- true factory reset / configuration erasure.

For S1, reaching re-onboarding/SoftAP is already a significant pivot even if a
true factory reset is not demonstrated.

### 3. Recovery mode exists, but the observed string argues against treating it as factory reset

`main` contains:

- `/tmp/recovery_mode`
- `[DS]IN RECOVERY MODE DONOT WRITE CONFIG !!!`
- `config.recover`
- `ds_config_recover`

The explicit "do not write config" message is evidence that **recovery mode is a
special state with configuration-write restrictions**, not evidence of a factory
reset. A crash/reboot into recovery must therefore be classified separately.

### 4. The physical reset path is present and separate

The binary has a `reset button` string and the rootfs ships GPIO-key handling via
`libsysutils.so`, including:

- `/sys/devices/platform/gpio-keys/keys`
- `/sys/devices/platform/gpio-keys/disabled_keys`
- `read key event error: %s`

No `long_press` string was found by the current seed scan. This confirms that a
hardware-reset path exists, but no static bridge from Wi-Fi events to that input
has been established.

### 5. Multiple WLAN implementations/tools are shipped

The rootfs contains or references:

- `rtl8188fu_wlan_operate`
- `wq9001_wlan_operate`
- `wpa_supplicant` related code
- `hostapd`
- `esp32.ko`

This is an implementation map, not proof that every component is active on the
C200 V5 hardware at runtime. Exact runtime driver selection still needs to be
established from boot logs/module state or static init logic.

## IMPORTANT FALSE-POSITIVE / CONFIDENCE RULES

The raw rootfs scanner searches printable strings in arbitrary files. Therefore
some hits are **not evidence of a feature**:

- `WPS`/`DPP` fragments inside `.g711` audio files are binary coincidences;
- `P2P` fragments inside unrelated song/font/binary assets are low-confidence;
- generic C++ `replace` symbols matched by the `csa` seed are noise;
- `hostapd` contains many deauth/disassoc/action-frame strings because it is an
  AP daemon. Their presence does not prove that the C200's NORMAL station path
  accepts those exact frames or that hostapd is running during NORMAL mode.

High-confidence static evidence should preferentially come from:

1. named symbols in `main`/shared libraries;
2. coherent log/config strings in executable code;
3. init scripts/configuration proving a component is started in a given state;
4. cross-references/callers connecting a Wi-Fi event to onboarding/recovery.

## STRONG HYPOTHESIS

The most promising S1 policy path is now:

`Wi-Fi link-status event -> wlan manager -> onboarding_phy_link_status_change_handle -> re-onboarding/SoftAP policy`

This is a **hypothesis**, not yet an exploit. The missing proof is the actual
branch condition: which link states, counters, timeouts, flags or reasons cause
onboarding/re-onboarding to start.

A second path remains possible:

`radio parser/driver fault -> reboot/recovery -> unsafe re-onboarding`

but the static result currently gives more direct evidence for a policy/state
machine path than for a memory-corruption path.

## NEXT STATIC TARGETS — P0

Reverse these functions before broad RF fuzzing:

1. `onboarding_phy_link_status_change_handle`
2. `wlan_manager_onboarding_start`
3. `onboarding_restart`
4. `wlan_manager_init_reconnect_ctx`
5. `wlan_manual_reconnect`
6. `wlan_manager_sta_disconnect` / `wlan_sta_disconnect`
7. `is_reonboarding` and `get_cur_onboarding_mode`
8. callers of `set_exit_softap_fast_flag` / `stop_exit_softap`
9. the code referencing `/tmp/recovery_mode`
10. the code referencing the `reset button` string

For each target, record:

- symbol address and size;
- direct/indirect callers;
- state fields read/written;
- retry counters/timeouts;
- reason/status codes;
- calls into SoftAP/onboarding/reboot/config APIs.

## NEXT DYNAMIC EXPERIMENT — only after the branch is mapped

The RF experiment should be designed from the recovered branch conditions rather
than from generic deauth flooding. A valid S1 trial must preserve:

- no association by the attacker;
- no PSK;
- no camera IP path;
- exact frame class/count/timestamps;
- pre/post device-state evidence;
- a control run;
- repeatability from a clean NORMAL state.

State classification remains:

`0 none -> 1 disconnect -> 2 reconnect -> 3 reboot -> 4 recovery -> 5 SoftAP/re-onboarding -> 6 unbound -> 7 verified factory reset`
