# Volatility notes for C200 V5

Volatility is not bundled and RootLab does not claim that Volatility 3 will
directly parse this custom MIPS/Linux 3.10.14 target.

Before relying on it, collect:

```text
uname -a
/proc/version
/proc/config.gz      (if enabled)
/proc/kallsyms       (if readable)
/proc/iomem
the exact kernel uImage
GPL kernel sources corresponding to the device build
```

Useful fallback if full Volatility support is awkward:

```text
/proc/<pid>/maps
gdbserver + gdb-multiarch dump memory
Ghidra static map of main/kernel
MTD before/after diff
custom Python structures over targeted process mappings
```

Do not interpret a symbol table from a merely similar 3.10.14 kernel as exact.
Kernel config/toolchain/patch differences change structure layouts.
