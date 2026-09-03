# v0.9.1 workflow corrections

Important first-run fixes:

- Fuzzers refuse to start unless their scoped target service is reachable.
- A snapshot with no reachable tested service is marked invalid.
- `state-report --auto` skips invalid/unreachable snapshots.
- `crash-oracle` prints a heartbeat about every 10 seconds.
- UART capture checks that the requested COM port actually exists.
- Flash/firmware commands fail cleanly when acquisition artifacts do not exist.

# Tapo C200 V5 — Memory / State Mapping Lab v0.9

This patch adds a separate entry point:

```powershell
python .\memorylab.py --help
```

It does not replace `blackbox.py` or `s1lab.py`.

## Objective

Turn the empirical transition:

```text
NORMAL
  ↓ physical factory reset
SETUP
```

into a reverse-engineering oracle:

```text
network / RF input
      ↓
parser
      ↓
userspace/kernel memory
      ↓
configuration/state manager
      ↓
SPI NOR state
      ↓
reboot/runtime decision
      ↓
NORMAL or SETUP
```

The end goal is to locate a path where a remotely reachable input can affect
the same state transition.

## Scope lock

Network fuzzers always load the camera IP from the existing project scope.
There is no subnet scanning and no arbitrary target argument.

Crash-oriented probes require:

```text
--arm
```

and stop immediately when the scoped camera becomes unavailable.

---

# Phase 1 — Create state snapshots

While the camera is normally configured:

```powershell
python .\memorylab.py snapshot --label NORMAL
```

In pairing/setup mode you can explicitly snapshot the setup gateway:

```powershell
python .\memorylab.py snapshot --label SETUP --ip 192.168.191.1
```

Each snapshot records:

```text
80/443/554/2020/8800
HTTPS login/discover
Streamd initial response
TDP v2 decrypted metadata/hashes if blackboxlab is present
```

Then:

```powershell
python .\memorylab.py state-report `
  --normal evidence\runs\<normal>\state-NORMAL.json `
  --setup evidence\runs\<setup>\state-SETUP.json `
  --out state-map.md
```

---

# Phase 2 — UART as the causal oracle

Install optional dependencies:

```powershell
pip install -r .\requirements-memorylab.txt
```

List adapters:

```powershell
python .\memorylab.py uart-ports
```

Typical capture:

```powershell
python .\memorylab.py uart-capture `
  --port COM5 `
  --baud 115200 `
  --seconds 240
```

Start capture first, then perform the physical state transition.

The analyzer searches for:

```text
Kernel Oops
panic
watchdog
reboot
factory/default/unbind/provision/softap
MTD/JFFS2/flash/erase
EPC
RA
SP
BadVA
Cause
```

If a parser probe later crashes the camera, the same UART capture can connect
the testcase to a MIPS fault address.

---

# Phase 3 — Full SPI NOR state diff

Use READ-ONLY acquisition methods from UART/U-Boot/SPI tooling.

Never write a raw dump back to flash merely to run this analysis.

Known research baseline:

```text
8 MiB SPI NOR

factory_boot  0x000000 - 0x02d800
factory_info  0x02d800 - 0x030000
art           0x030000 - 0x040000
config        0x040000 - 0x050000
normal_boot   0x050000 - 0x070000
kernel        0x070200 - 0x1b0000
rootfs        0x1b0000 - 0x3d0000
rootfs_data   0x3d0000 - 0x770000
user_record   0x770000 - 0x7f0000
verify        0x7f0000 - 0x800000
```

Verify that layout against the actual unit before interpreting offsets.

Carve a dump:

```powershell
python .\memorylab.py flash-carve `
  .\dumps\normal.bin `
  --out .\analysis\normal-carved
```

Do the same with the SETUP dump.

Then:

```powershell
python .\memorylab.py flash-diff `
  .\dumps\normal.bin `
  .\dumps\setup.bin `
  --out .\analysis\flash-normal-vs-setup
```

Outputs:

```text
flash-diff.json
changed-runs.csv
changed-pages.csv
```

The useful question is not merely "what changed?", but:

```text
which partition?
which 4 KiB pages?
which exact byte runs?
wipe to 00/FF?
nearby printable state names?
```

A very small changed region in `config`, `rootfs_data` or `user_record` is a
prime reverse-engineering target.

---

# Phase 4 — Filesystem diff

After extracting/carving the relevant filesystems:

```powershell
python .\memorylab.py dir-diff `
  .\fs\normal `
  .\fs\setup `
  --out .\analysis\fs-diff
```

This identifies added/removed/modified files by SHA-256.

Then index strings across the extracted firmware:

```powershell
python .\memorylab.py firmware-index `
  .\fs\normal `
  --out .\analysis\firmware-index
```

Keyword groups include:

```text
factory_reset / factory_default
reset_wifi
unbind / binding
provision / pairing / softap
watchdog / reboot
/dev/mtd / erase / flash
/stream / Authorization
pake_register / default_userpw
strcpy / sprintf / memcpy / system / ioctl
```

Use `firmware-hits.csv` to prioritize the large `main` userspace binary and
configuration libraries.

---

# Phase 5 — Approximate MIPS string-to-code xrefs

For an ELF binary from the firmware:

```powershell
python .\memorylab.py mips-map `
  .\fs\normal\path\to\main `
  --out .\analysis\main-mips
```

This uses Capstone + pyelftools and reports:

- matching strings with ELF virtual addresses;
- approximate MIPS `LUI + ADDIU/ORI` references to those strings;
- interesting symbols/imports when present;
- code-address context to navigate directly in Ghidra.

This is intentionally a triage engine, not a replacement for Ghidra.

Typical workflow:

```text
flash diff says config offset changed
        ↓
firmware-index finds factory/bind strings
        ↓
mips-map gives code address candidates
        ↓
Ghidra xrefs
        ↓
writer function
        ↓
callers
        ↓
network / IPC handler
```

---

# Phase 6 — Dynamic crash oracle

In one terminal:

```powershell
python .\memorylab.py crash-oracle --seconds 300
```

Ideally run UART capture in parallel.

The oracle records transitions:

```text
TARGET_UP
TARGET_DOWN
TARGET_UP
```

If a testcase makes the camera disappear, the corresponding fuzzer stops
immediately.

---

# Phase 7 — Bounded pre-auth parser regression probes

These are deliberately opt-in.

## RTSP Authorization

```powershell
python .\memorylab.py rtsp-auth-fuzz --arm
```

This performs deterministic boundary-length tests against the scoped C200 only.

It is useful because the same hardware generation previously had a pre-auth
RTSP Authorization parser overflow, although the current firmware is expected
to contain the published fix.

## Streamd multipart boundary

```powershell
python .\memorylab.py streamd-boundary-fuzz --arm
```

## HTTPS JSON method dispatcher

```powershell
python .\memorylab.py https-json-fuzz --arm
```

All three:

- use deterministic payloads;
- save request SHA-256 fingerprints;
- check whether the camera is alive after every case;
- stop immediately on a target-down transition.

The first objective is crash localization, not code execution.

---

# High-value outcome classes

```text
A — normal parser rejection
B — service process restart
C — kernel Oops with EPC/BadVA
D — watchdog reboot
E — reboot followed by NORMAL
F — reboot followed by Tapo_Cam_XXXX / SETUP
```

`F` is the direct state-pivot candidate.

`C` is highly useful even without F because EPC/RA/BadVA can be mapped to the
firmware binary and converted into a precise memory-corruption root cause.

---

# Recommended immediate order

1. Re-pair the camera and capture a clean NORMAL snapshot.
2. Attach UART and capture a physical factory reset.
3. Acquire a full NORMAL SPI NOR dump.
4. Factory reset under UART.
5. Acquire a full SETUP SPI NOR dump.
6. Run `flash-diff`.
7. Index/extract firmware and run `firmware-index`.
8. Run `mips-map` on `main`.
9. Only then run bounded parser fuzzing with UART attached.

Do not fuzz blindly before you have UART: a reboot is far more valuable when
you also capture EPC/RA/BadVA and the boot reason.
