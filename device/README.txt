RootLab device bundle.

collect.sh
  Snapshot CPU, kernel, /proc, MTD layout, main PID/maps/fds.

reset_capture.sh
  Attach optional strace + IRQ/GPIO sampler and persist evidence while you
  physically press RESET.

start_gdbserver.sh
  Attach a user-supplied MIPSLE gdbserver to process "main".

mtd_snapshot.sh
  Read-only dump of exposed /dev/mtdblock* nodes.

process_watch.sh
  Lightweight process-state sampler.

Optional static tools go in /opt/rootlab/bin.
RootLab does not ship third-party MIPS binaries.
