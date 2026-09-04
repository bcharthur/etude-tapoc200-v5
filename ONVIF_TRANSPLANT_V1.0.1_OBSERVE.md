# v1.0.1 — passive baseline + single-shot causal oracle

The prior extended-elements run observed a transient ONVIF outage only between
testcases:

```text
case elements=1 completed while :2020 still looked alive
next pre-case check found :2020 down
later manual probes showed :2020 recovered
```

That is a useful signal, but the run also started with `:8800` unavailable.
Therefore the service state was not completely stable and causality was not yet
established.

v1.0.1 adds two commands.

## 1. Passive observation

```powershell
python .\onviflab.py observe `
  --state setup `
  --seconds 180
```

Default sampling interval is 250 ms.

This sends **no ONVIF mutation body**. HTTPS discovery is checked periodically
only to confirm the scoped camera remains alive.

Goal:

```text
180 s passive
443/554/2020/8800 remain stable
```

If :2020 naturally disappears during this period, the earlier result cannot be
attributed to `CreateRules` without additional evidence.

## 2. Single testcase with PRE/POST windows

If passive observation is stable:

```powershell
python .\onviflab.py single `
  --state setup `
  --axis elements `
  --value 1 `
  --pre-seconds 30 `
  --post-seconds 120 `
  --interval 0.25 `
  --arm
```

The command:

```text
30 s passive PRE window
→ require :2020 UP at end
→ send exactly ONE elements=1 CreateRules request
→ 120 s passive POST window at 250 ms resolution
```

It classifies the result as:

```text
NO_ONVIF_OUTAGE_OBSERVED

POST_REQUEST_ONVIF_OUTAGE_OBSERVED_PRE_WINDOW_STABLE

ONVIF_OUTAGES_EXIST_IN_BOTH_PRE_AND_POST_WINDOWS
```

This is much stronger evidence than a fast sweep because it separates natural
service instability from a delayed parser-triggered restart.

Do not run `elements extended` again until this experiment is complete.
