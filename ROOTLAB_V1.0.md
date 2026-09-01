# Tapo C200 V5 RootLab v1.0

## Goal

Build a controlled hardware/dynamic-analysis environment for an owned C200 V5:

```text
UART / U-Boot
   ↓
8 MiB NOR backup
   ↓
rootfs extraction
   ↓
LAB root password + instrumentation bundle
   ↓
repacked firmware
   ↓
root login over UART
   ↓
CPU / /proc / MTD / process memory
   ↓
strace + IRQ/GPIO capture during physical RESET
   ↓
GDB / memory dumps / offline diff
```

This toolkit deliberately does **not** automatically execute a flash write.
It builds artifacts and prints the reviewed U-Boot commands.

---

## Hardware caution

For the Rev.5 hardware, published research reports that RX/TX may be disconnected
by unpopulated 0-ohm resistor positions. Use the CPU-side pads/appropriate board
modification only if you are comfortable with PCB work.

Verify UART logic voltage with a meter/scope/logic analyzer. Do not assume Vcc.
For console work you normally need common GND and crossed TX/RX; do not connect
the adapter Vcc blindly.

---

## 0. Install host dependency

```powershell
pip install -r .\requirements-rootlab.txt
```

For SquashFS extraction/repacking, install in WSL:

```bash
sudo apt update
sudo apt install squashfs-tools
```

Optional later:
- a **static MIPS little-endian** `strace`
- a **static MIPS little-endian** `gdbserver`
- host `gdb-multiarch`

RootLab does not redistribute those third-party binaries. Put them in a folder,
for example:

```text
payloads\mipsel\
  strace
  gdbserver
```

Verify each before injection:

```powershell
python .\rootlab.py tool-check .\payloads\mipsel\strace
```

Expected ELF machine number for MIPS is `8`, little-endian `true`.

---

# 1. UART

List adapters:

```powershell
python .\rootlab.py serial-list
```

Open interactive console:

```powershell
python .\rootlab.py console --port COM6 --baud 115200
```

Capture boot/reset UART independently:

```powershell
python .\rootlab.py uart-capture `
  --port COM6 `
  --baud 115200 `
  --seconds 300 `
  --out .\evidence\uart-boot.jsonl
```

At U-Boot, published Rev.5 research reports that typing:

```text
slp
```

interrupts boot.

---

# 2. Acquire an untouched NOR backup

Print acquisition commands:

```powershell
python .\rootlab.py uboot-dump-plan
```

The read-only U-Boot sequence is:

```text
sf probe
sf read 0x80600000 0x0 0x000000800000
mmc write 0x80600000 0 16384
```

Acquire exactly 8 MiB from the SD card on the host.

Immediately:

```powershell
python .\rootlab.py dump-info .\dumps\original.bin
python .\rootlab.py carve .\dumps\original.bin --out .\analysis\carved
```

Keep at least two copies of the original dump and its SHA-256.

---

# 3. Inspect kernel and recover the rootfs header key

```powershell
python .\rootlab.py kernel-info .\analysis\carved\kernel.bin
```

RootLab parses the legacy U-Boot uImage, decompresses its LZMA payload, and
searches the decompressed kernel for 16-byte printable strings beginning
`TP_LINK`.

It does **not** silently assume that the key from another firmware build is
correct.

---

# 4. Decrypt and extract rootfs

```powershell
python .\rootlab.py decrypt-rootfs `
  .\dumps\original.bin `
  --out .\analysis\rootfs.squashfs
```

The tool:
- auto-recovers the key from this dump's own kernel;
- decrypts only the first 512 bytes with AES-128-CFB1;
- requires the result to begin with SquashFS magic `hsqs`.

Extract:

```powershell
python .\rootlab.py extract-rootfs `
  .\analysis\rootfs.squashfs `
  --out .\analysis\rootfs-tree
```

---

# 5. Patch LAB root access and inject instrumentation

Without external tools:

```powershell
python .\rootlab.py patch-rootfs `
  --tree .\analysis\rootfs-tree
```

It prompts for a new root password and modifies only the `root` hash in
`/etc/shadow`, preserving a backup inside the extracted tree.

To also inject your static MIPSLE `strace` and `gdbserver`:

```powershell
python .\rootlab.py patch-rootfs `
  --tree .\analysis\rootfs-tree `
  --tool-dir .\payloads\mipsel
```

RootLab injects its own shell scripts under:

```text
/opt/rootlab/
```

It does **not** add a persistent network listener to boot. Root is obtained
through the serial login prompt; gdbserver is started manually when needed.

---

# 6. Repack and build modified 8 MiB image

```powershell
python .\rootlab.py repack-rootfs `
  --tree .\analysis\rootfs-tree `
  --out .\analysis\rootfs-rootlab.squashfs
```

Then:

```powershell
python .\rootlab.py build-image `
  --original .\dumps\original.bin `
  --rootfs .\analysis\rootfs-rootlab.squashfs `
  --out .\images\c200v5-rootlab.bin
```

The builder:
- refuses a rootfs larger than its fixed partition;
- encrypts only its first 512 bytes;
- preserves every byte outside the rootfs partition from your original dump;
- performs an AES-CFB1 round-trip verification;
- emits SHA-256 metadata.

---

# 7. Flash / recovery plan

Review only:

```powershell
python .\rootlab.py flash-plan `
  --image .\images\c200v5-rootlab.bin `
  --arm
```

The command prints the documented U-Boot flow but never executes it.

Keep `original.bin` on a separate recovery SD card before modifying anything.

---

# 8. First root boot

After booting the modified image, use UART:

```text
login: root
password: <your LAB password>
```

Then:

```sh
/opt/rootlab/collect.sh /mnt/sd/rootlab-baseline
```

This saves:
- `/proc/cpuinfo`
- `/proc/meminfo`
- `/proc/iomem`
- `/proc/interrupts`
- `/proc/mtd`
- mounts/partitions/modules
- dmesg
- process list
- PID/maps/status/fds of `main`
- `/proc/config.gz` when available
- GPIO debug state when available

---

# 9. Capture the physical factory-reset path

If `strace` is injected:

```sh
/opt/rootlab/reset_capture.sh /mnt/sd/rootlab-reset-01
```

Then perform exactly one physical RESET.

Before the reboot it attempts to persist:
- complete pre-state;
- `strace -ff -tt -T -s 512` of process `main`;
- `/proc/interrupts` repeatedly;
- debug GPIO state if exposed;
- frequent `sync`.

After the camera returns in SETUP, remove/read the microSD and inspect the
artifacts.

The target causal chain is:

```text
physical button
 → GPIO/IRQ change
 → main read/ioctl/signal/IPC
 → config/MTD operation
 → reboot
 → SETUP
```

---

# 10. GDB process-memory dumps

Start on the camera:

```sh
/opt/rootlab/start_gdbserver.sh 2345
```

Copy the saved `/proc/<main>/maps` to the PC, then:

```powershell
python .\rootlab.py gdb-dump-script `
  --maps .\evidence\main.maps `
  --out .\analysis\dump-main.gdb `
  --remote 192.168.1.79:2345 `
  --dump-dir .\memdump `
  --writable-only
```

Run:

```bash
gdb-multiarch -x analysis/dump-main.gdb
```

The generated script dumps only readable regions, with a default 32 MiB
per-region ceiling. `--writable-only` focuses on heap/stack/data state.

Use this for controlled snapshots before selected state changes. A physical
full reset destroys the old process, so the strongest reset evidence remains
strace/IRQ/flash plus pre-reset memory snapshots.

---

# 11. Physical RAM acquisition

First collect:

```text
/proc/iomem
```

Then on the host:

```powershell
python .\rootlab.py ram-dump-script `
  --iomem .\evidence\iomem.txt `
  --out .\analysis\dump-system-ram.sh `
  --destination /mnt/sd/rootlab-ram
```

The generated device script:
- reads only regions whose label is exactly `System RAM`;
- never reads arbitrary MMIO regions;
- refuses unaligned ranges rather than rounding into adjacent address space.

Run it only after reviewing `/proc/iomem`.

`/dev/mem` may be restricted by the kernel; failure is a valid result.

---

# 12. Volatility

Treat Volatility as an **optional later layer**, not the acquisition method.

For this target you need to determine whether Volatility 3 can consume the
MIPS/Linux-3.10.14 memory image you obtain and create symbols matching the
**exact** TP-Link kernel build.

RootLab therefore preserves the raw inputs needed for either:
- Volatility, if exact symbol support is workable;
- custom GDB/Ghidra/Python parsers otherwise.

For the reset investigation, `/proc`, strace, GDB and MTD diffs are likely to
produce useful answers sooner.

---

# Recommended experiment

```text
A. Rooted NORMAL
   collect.sh
   process memory snapshot
   MTD snapshot

B. Arm reset_capture.sh

C. Physical RESET once

D. SETUP
   collect.sh again
   MTD snapshot again

E. Offline:
   UART + IRQ timeline
   strace timeline
   MTD diff
   process/main static reverse in Ghidra
```

Then search callers of the function that performs the reset/config erase and
determine whether any remotely reachable parser/IPC/network command reaches it.
