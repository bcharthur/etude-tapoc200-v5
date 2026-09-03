#!/bin/sh
set -eu

OUT="${1:-/tmp/rootlab-collect}"
mkdir -p "$OUT"

save() {
    name="$1"
    shift
    { "$@" 2>&1 || true; } > "$OUT/$name"
}

save uname.txt uname -a
save cpuinfo.txt cat /proc/cpuinfo
save meminfo.txt cat /proc/meminfo
save iomem.txt cat /proc/iomem
save interrupts.txt cat /proc/interrupts
save mtd.txt cat /proc/mtd
save mounts.txt cat /proc/mounts
save partitions.txt cat /proc/partitions
save cmdline.txt cat /proc/cmdline
save modules.txt cat /proc/modules
save devices.txt cat /proc/devices
save filesystems.txt cat /proc/filesystems
save version.txt cat /proc/version
save uptime.txt cat /proc/uptime
save dmesg.txt dmesg
save ps.txt ps
save net_dev.txt cat /proc/net/dev
save net_tcp.txt cat /proc/net/tcp
save net_udp.txt cat /proc/net/udp

if [ -r /proc/config.gz ]; then
    cp /proc/config.gz "$OUT/config.gz"
fi

if [ -r /sys/kernel/debug/gpio ]; then
    cat /sys/kernel/debug/gpio > "$OUT/gpio-debug.txt" 2>&1 || true
fi

PID="$(pidof main 2>/dev/null | awk '{print $1}' || true)"
if [ -z "$PID" ]; then
    PID="$(ps | awk '$0 ~ /[[:space:]\/]main([[:space:]]|$)/ {print $1; exit}')"
fi

echo "${PID:-}" > "$OUT/main.pid"

if [ -n "${PID:-}" ] && [ -d "/proc/$PID" ]; then
    cp "/proc/$PID/maps" "$OUT/main.maps" 2>/dev/null || true
    cp "/proc/$PID/status" "$OUT/main.status" 2>/dev/null || true
    cp "/proc/$PID/limits" "$OUT/main.limits" 2>/dev/null || true
    cp "/proc/$PID/cmdline" "$OUT/main.cmdline" 2>/dev/null || true
    mkdir -p "$OUT/main-fd"
    for x in /proc/"$PID"/fd/*; do
        [ -e "$x" ] || continue
        n="$(basename "$x")"
        readlink "$x" > "$OUT/main-fd/$n.txt" 2>/dev/null || true
    done
fi

sync
echo "RootLab inventory saved to $OUT"
