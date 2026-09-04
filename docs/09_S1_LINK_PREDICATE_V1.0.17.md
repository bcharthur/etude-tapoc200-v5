# S1 — exact link-status → onboarding predicate (v1.0.17)

## Why this step exists

v1.0.16 recovered a direct static edge:

`onboarding_phy_link_status_change_handle`
→ `wlan_manager_onboarding_start`

This is the strongest static bridge found so far between a Wi-Fi physical-link
state handler and onboarding logic.

It is **not yet proof** that arbitrary unauthenticated radio traffic can take
that branch, nor that onboarding means factory reset.

## v1.0.17 objective

Slice the exact instructions immediately preceding every relevant call from the
link-status handler. Preserve:

- branch mnemonic and operands;
- branch target;
- call site;
- instruction window;
- nearby referenced strings;
- raw caller sites, including caller sites that cannot be assigned a symbol.

This is intended to reveal the runtime predicate we need to reproduce later,
e.g. a status/reason enum, AP/monitor state, retry condition, or mode flag.

## Command

```powershell
.\scripts\export-s1-link-predicate.ps1
```

Outputs:

```text
analysis\s1-link-predicate\
  s1-link-predicate.md
  s1-link-predicate.json
  onboarding_phy_link_status_change_handle.disasm.txt
  context-functions\
    wlan_manager_onboarding_start.disasm.txt
    wlan_manager_start.disasm.txt
    ...
```

## Evidence labels

**CONFIRMÉ** — a direct static call from the link-status handler into onboarding
exists if the generated report says so.

**À TESTER** — the exact input/status values that select that branch.

**NON DÉMONTRÉ** — RF-only factory reset. Re-onboarding/SoftAP is a separate
milestone from configuration erasure/unbinding.
