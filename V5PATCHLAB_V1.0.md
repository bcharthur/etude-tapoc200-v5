# Tapo C200 V5 PatchLab v1.0

## Objective

Stop transplanting C200 V3 parser bugs and compare the **same C200 V5 codebase**
across the security boundary:

```text
C200 V5 1.4.4 Build 260527
        ↓
       diff
        ↓
C200 V5 1.4.6 Build 260709 Rel.27675n
```

The public CVE records say both:

```text
CVE-2026-15315
CVE-2026-15316
```

affect C200 V5 versions **before** `V5_1.4.6 Build 260709 Rel.27675n`.

This does not mean every change between 1.4.4 and 1.4.6 is a security fix.
1.4.6 also contains ordinary performance/stability changes. The purpose of the
lab is to narrow the candidate functions, then verify them in Ghidra.

---

## CVE focus

### CVE-2026-15315

Public vendor description:

```text
login authentication verification module
→ weaknesses in challenge parameter validation
→ bypass normal authentication
→ administrative session tokens
→ privileged management actions
```

Priority seeds:

```text
device_confirm
dev_confirm
challenge
nonce / cnonce
login
session / stok / token
pake_register
pake_share
verify
digest
```

### CVE-2026-15316

Public vendor description:

```text
configuration service
→ encrypted credential data
→ oversized ciphertext values
→ insufficient validation / exception handling
→ crash or restart
```

Priority seeds:

```text
ciphertext
credential
changeThirdAccount
third_account
user_management
base64
RSA
decrypt
malloc
memcpy
strlen
exception/error
```

---

# 1. Install Python analysis dependencies

From your Windows virtualenv:

```powershell
pip install -r .\requirements-v5patchlab.txt
```

Then:

```powershell
python .\v5patchlab.py env-check
```

Your WSL Ubuntu already has `squashfs-tools`; PatchLab additionally benefits
from `binwalk`, `git`, `gcc` and OpenSSL development headers.

You can run:

```powershell
wsl -d Ubuntu
```

then inside Ubuntu:

```bash
cd /mnt/c/Users/<you>/PycharmProjects/etude-tapoc200-v5
bash scripts/setup-v5patchlab-wsl.sh
```

The script clones the public `robbins/tp-link-decrypt` repository, runs its
published key-extraction procedure and builds it.

`tp-link-decrypt` does not sign firmware and PatchLab does not flash anything.

---

# 2. Find the exact public firmware objects

TP-Link's firmware bucket is publicly listable. PatchLab only queries the
narrow prefix:

```text
firmware/Tapo_C200v5
```

Find old:

```powershell
python .\v5patchlab.py firmware-find `
  --version 1.4.4 `
  --build 260527
```

Find fixed:

```powershell
python .\v5patchlab.py firmware-find `
  --version 1.4.6 `
  --build 260709
```

If there are multiple regions, use the EU object matching the tested camera.

Download only a key returned by `firmware-find`:

```powershell
python .\v5patchlab.py firmware-download `
  --key "<exact key returned above>" `
  --out .\firmware\c200v5-1.4.4.bin
```

and:

```powershell
python .\v5patchlab.py firmware-download `
  --key "<exact key returned above>" `
  --out .\firmware\c200v5-1.4.6.bin
```

Every download is SHA-256 hashed.

---

# 3. Decrypt the signed OTA package

The research tool `tp-link-decrypt` writes:

```text
<input>.dec
```

PatchLab wraps it through Ubuntu WSL:

```powershell
python .\v5patchlab.py decrypt .\firmware\c200v5-1.4.4.bin

python .\v5patchlab.py decrypt .\firmware\c200v5-1.4.6.bin
```

The wrapper verifies the resulting `.dec` file exists and records both hashes.

Important:

The public Evilsocket workflow demonstrated `tp-link-decrypt` on C200 V3 and
reported that TP-Link camera firmware uses the same package mechanism broadly.
PatchLab **tests** the V5 packages rather than assuming compatibility. If the
tool rejects V5, preserve the exact output; that becomes the next extraction
problem rather than silently falling back to a guessed key.

---

# 4. Inspect and extract

Before binwalk:

```powershell
python .\v5patchlab.py magic-scan `
  .\firmware\c200v5-1.4.4.bin.dec

python .\v5patchlab.py magic-scan `
  .\firmware\c200v5-1.4.6.bin.dec
```

Then:

```powershell
python .\v5patchlab.py extract `
  .\firmware\c200v5-1.4.4.bin.dec `
  --out .\analysis\144

python .\v5patchlab.py extract `
  .\firmware\c200v5-1.4.6.bin.dec `
  --out .\analysis\146
```

Extraction uses `binwalk -eM` from WSL and preserves the extraction tree.

---

# 5. Locate the V5 userspace service binary

```powershell
python .\v5patchlab.py find-main .\analysis\144
python .\v5patchlab.py find-main .\analysis\146
```

Candidates are ranked by:

```text
filename == main
+
ELF
+
device_confirm
pake_register / pake_share
ciphertext
securePassthrough
third_account
changeThirdAccount
ONVIF
/stream
```

Use the **corresponding `/bin/main` from each build** for the diff.

---

# 6. Generate the focused patch report

```powershell
python .\v5patchlab.py report `
  --old "<path to 1.4.4 main>" `
  --new "<path to 1.4.6 main>" `
  --out .\analysis\patch-144-vs-146
```

Outputs:

```text
analysis/patch-144-vs-146/
├── patch-report.json
└── patch-report.md
```

The JSON contains:

- SHA-256 + sizes
- raw positional changed-byte runs
- strings added/removed
- seed-string presence in each build
- MIPS little-endian approximate xrefs for each CVE seed
- local disassembly context around each materialized string address
- nearby `jal`/`bal` calls when visible

The xref engine recognizes common MIPS address construction:

```text
lui reg, HI
addiu/ori reg, reg, LO
```

This is a **navigation heuristic**, not a replacement for Ghidra.

---

# 7. Ghidra workflow

Load both binaries:

```text
Architecture: MIPS little endian 32-bit
```

Start with `patch-report.json`.

For CVE-2026-15315, compare functions around:

```text
device_confirm
challenge
nonce/cnonce
session token
pake/login verification
```

Specifically look for a 1.4.6 change like:

```c
if (!challenge_is_current(...))
    reject();

if (memcmp(expected_confirm, supplied_confirm, N) != 0)
    reject();

if (nonce_reused(...))
    reject();
```

Those are **illustrative shapes only**; do not assume this exact patch.

For CVE-2026-15316, compare:

```text
ciphertext decode
credential parsing
base64 decode
RSA decrypt
allocation
copy
exception/error handling
```

High-value patch shapes are:

```c
if (ciphertext_len > MAX)
    return error;
```

or:

```c
decoded = base64_decode(...)
if (decoded_len != expected)
    reject();
```

Again: illustrative patterns, not claims about TP-Link's code.

---

# 8. What warrants a new network test

Do not fuzz the current camera merely because code changed.

A new network test is justified when the diff shows a concrete boundary, e.g.:

```text
1.4.4:
  decode ciphertext before checking encoded length

1.4.6:
  explicit max length check added before decode
```

Then build a bounded regression matrix around that exact limit.

Or for authentication:

```text
1.4.4:
  accepts/reuses a challenge parameter without freshness comparison

1.4.6:
  new challenge/nonce relation is validated
```

Then reproduce only that exact state machine.

This produces much higher-quality evidence than blind payload growth.

---

# Safety/experimental boundaries

PatchLab:

- downloads public firmware only;
- performs offline decryption/extraction/diff;
- does not flash firmware;
- does not downgrade the camera;
- does not contain shellcode/ROP/persistence;
- does not send network exploit traffic;
- does not search arbitrary internet cameras.

The eventual network harness should remain scoped to the camera in
`config/scope.json`.


## Current preferred acquisition branch

```powershell
python .\v5patchlab.py cloud-account-fw
python .\v5patchlab.py cloud-account-fw --arm
```
