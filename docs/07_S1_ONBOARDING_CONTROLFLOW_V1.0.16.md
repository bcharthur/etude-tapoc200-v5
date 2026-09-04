# S1 — onboarding/link-state control-flow, v1.0.16

## Why this pass exists

The v1.0.15 static map reduced the original S1 question to one high-value junction:

`onboarding_phy_link_status_change_handle`

The firmware also exposes explicit WLAN disconnect/reconnect functions, re-onboarding state, onboarding start/restart and SoftAP exit/start flags. The next useful question is therefore no longer “does this firmware contain Wi-Fi and onboarding code?” but:

> Which exact caller, status/reason input, counter, timeout or branch can move a normal bound camera from a WLAN link event into re-onboarding/SoftAP?

## Command

```powershell
.\scripts\export-s1-onboarding-controlflow.ps1
```

or directly:

```powershell
python .\v5patchlab.py s1-controlflow `
  .\analysis\c200v5-142\main-1.4.2 `
  --out .\analysis\s1-onboarding-controlflow
```

## Outputs

- `s1-controlflow.json`: machine-readable graph and branch/call/string evidence.
- `s1-controlflow.md`: ranked human-readable summary.
- `s1-controlflow.dot`: Graphviz call graph seed.
- `functions/*.disasm.txt`: exact MIPS disassembly for each S1 target.
- `functions/*.json`: calls, callers, branches, indirect calls and materialized strings.

## What the analyzer resolves

`CONFIRMÉ`:

- symbol address and size from the ELF;
- direct `bal` / `jal` / `jalx` calls;
- direct callers of the selected S1 functions;
- branch targets emitted by `objdump`;
- likely `.rodata` string references reconstructed from `lui` + `addiu/ori` address materialization;
- unresolved `jalr` calls are retained explicitly rather than guessed.

`HYPOTHÈSE`:

- a function ranked as a “bridge candidate” may connect link-state to onboarding/SoftAP, but static proximity is not proof that an unauthenticated 802.11 event can trigger it.

## P0 reading order

1. `onboarding_phy_link_status_change_handle`
2. its direct callers
3. `wlan_manager_sta_disconnect` / `wlan_sta_disconnect` / `disconnect_WiFi_ex`
4. `wlan_manager_init_reconnect_ctx` / `wlan_manual_reconnect`
5. `is_reonboarding` / `get_cur_onboarding_mode`
6. `wlan_manager_onboarding_start` / `onboarding_restart`
7. `set_exit_softap_fast_flag` / `stop_exit_softap`
8. reboot functions only if the branch actually reaches them

The useful result is a concrete predicate such as a reason code, status value, retry counter or timeout. Only then should the radio test be shaped around that exact condition.

## S1 success condition remains strict

A deauthentication, disconnect, crash, reboot or `/tmp/recovery_mode` is not a factory reset.

The target remains:

`NORMAL/bound -> radio-only event -> re-onboarding/SoftAP/unbound/factory`

with no PSK, no association to the protected WLAN, no camera IP path and no physical action.
