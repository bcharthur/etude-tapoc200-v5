#!/bin/sh
set -eu

OUT="${1:-/mnt/sd/rootlab-mtd}"
mkdir -p "$OUT"

cat /proc/mtd > "$OUT/proc-mtd.txt"

# READ ONLY. Dump available mtdblock nodes if the kernel exposes them.
for dev in /dev/mtdblock*; do
    [ -e "$dev" ] || continue
    name="$(basename "$dev")"
    echo "Reading $dev -> $OUT/$name.bin"
    dd if="$dev" of="$OUT/$name.bin" bs=65536 2>"$OUT/$name.dd.log" || true
    sync
done

echo "MTD read-only snapshot complete: $OUT"
