# Memorylab v0.9.1 — preflight / workflow fixes

This patch fixes problems exposed by the first real run.

## What happened

The SETUP snapshot was valid.

The attempted NORMAL snapshot was NOT valid because the camera was still
factory-reset / pairing and therefore no longer reachable at `192.168.1.79`.

All three fuzz runs were therefore meaningless:

```text
target_alive_before = false
target_alive_after  = false
```

No parser was reached.

v0.9.1 refuses to send even the first testcase unless the specific scoped
service is reachable first:

```text
rtsp-auth-fuzz         requires 192.168.1.79:554 OPEN
streamd-boundary-fuzz requires 192.168.1.79:8800 OPEN
https-json-fuzz        requires 192.168.1.79:443 OPEN
```

## Correct next workflow

The existing SETUP snapshot is good:

```text
evidence\runs\20260903T135252Z-state\state-SETUP.json
```

Now re-pair the camera normally.

Wait until the scoped IP responds again, then:

```powershell
python .\memorylab.py snapshot --label NORMAL
```

A valid NORMAL snapshot must show at least one tested service reachable and
should normally recover the already observed 443/554/2020/8800 surface.

Then:

```powershell
python .\memorylab.py state-report --auto `
  --out .\analysis\normal-vs-setup.md
```

No literal `<NORMAL>` / `<SETUP>` placeholders are needed anymore.

## UART

`uart-ports` returning an empty list means no physical serial adapter is
connected to Windows.

`COM5` in the README was an example, not a known port on the user's PC.

v0.9.1 now refuses with a short explanation instead of a pyserial traceback.

## Flash and firmware commands

These commands analyze artifacts; they do not magically acquire them.

Therefore:

```text
dumps\normal.bin
dumps\setup.bin
fs\normal
path\to\main
```

must actually exist first.

v0.9.1 gives a short preflight error instead of a Python traceback when they
do not.

## Crash oracle

The old oracle looked blank because it printed only after the requested time
window ended.

v0.9.1 prints:

```text
[crash-oracle] ... UP open=['443', '554', ...]
```

about every 10 seconds and immediately on UP/DOWN transitions.
