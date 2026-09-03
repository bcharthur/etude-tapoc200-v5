#!/bin/sh
set -eu

# Usage:
#   /opt/rootlab/reset_capture.sh /mnt/sd/rootlab-reset
#
# Start this while camera is stable, then physically hold RESET.
# Store on microSD or another persistent mount because the camera will reboot.

OUT="${1:-/mnt/sd/rootlab-reset}"
mkdir -p "$OUT"

echo "rootlab reset capture started" > "$OUT/README.txt"
date >> "$OUT/README.txt" 2>/dev/null || true

/opt/rootlab/collect.sh "$OUT/pre" || true

PID="$(cat "$OUT/pre/main.pid" 2>/dev/null || true)"
STRACE=""

if [ -x /opt/rootlab/bin/strace ]; then
    STRACE=/opt/rootlab/bin/strace
elif command -v strace >/dev/null 2>&1; then
    STRACE="$(command -v strace)"
fi

# High-value IRQ/GPIO sampler. Never writes to hardware state.
(
    while :; do
        echo "===== SAMPLE ====="
        date 2>/dev/null || true
        cat /proc/interrupts 2>/dev/null || true
        if [ -r /sys/kernel/debug/gpio ]; then
            cat /sys/kernel/debug/gpio 2>/dev/null || true
        fi
        sync
        if command -v usleep >/dev/null 2>&1; then
            usleep 200000
        else
            sleep 1
        fi
    done
) >> "$OUT/interrupts-live.log" 2>&1 &
SAMPLE_PID=$!

# Flush trace files frequently so the physical reset doesn't lose everything.
(
    while :; do
        sync
        sleep 1
    done
) &
SYNC_PID=$!

if [ -n "$STRACE" ] && [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
    echo "Attaching strace to main PID=$PID" | tee -a "$OUT/README.txt"
    "$STRACE" -ff -tt -T -s 512 \
        -o "$OUT/main.strace" \
        -p "$PID" \
        >/dev/null 2>&1 &
    TRACE_PID=$!
else
    TRACE_PID=""
    echo "strace unavailable or main PID missing; IRQ/proc capture only" \
        | tee -a "$OUT/README.txt"
fi

echo ""
echo "=============================================================="
echo "CAPTURE ARMED."
echo "Now perform ONE physical RESET operation on the camera."
echo "The reboot is expected to terminate this script."
echo "Artifacts should persist under: $OUT"
echo "=============================================================="
echo ""

# Keep shell alive until reboot/process death/manual stop.
while :; do
    if [ -n "$PID" ] && [ ! -d "/proc/$PID" ]; then
        echo "main process disappeared before system reboot" >> "$OUT/README.txt"
        sync
        break
    fi
    sleep 1
done

kill "$SAMPLE_PID" "$SYNC_PID" ${TRACE_PID:-} 2>/dev/null || true
sync
