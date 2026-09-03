#!/bin/sh
set -eu

OUT="${1:-/mnt/sd/rootlab-process-watch}"
mkdir -p "$OUT"

while :; do
    echo "===== $(date 2>/dev/null || echo now) ====="
    ps
    PID="$(pidof main 2>/dev/null | awk '{print $1}' || true)"
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        echo "MAIN_PID=$PID"
        cat "/proc/$PID/status" 2>/dev/null || true
    else
        echo "MAIN_MISSING"
    fi
    sync
    sleep 1
done >> "$OUT/watch.log" 2>&1
