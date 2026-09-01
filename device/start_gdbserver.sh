#!/bin/sh
set -eu

PORT="${1:-2345}"

if [ -x /opt/rootlab/bin/gdbserver ]; then
    GDBSERVER=/opt/rootlab/bin/gdbserver
elif command -v gdbserver >/dev/null 2>&1; then
    GDBSERVER="$(command -v gdbserver)"
else
    echo "gdbserver not found. Inject a static MIPSLE gdbserver into /opt/rootlab/bin."
    exit 2
fi

PID="$(pidof main 2>/dev/null | awk '{print $1}' || true)"
if [ -z "$PID" ]; then
    echo "main PID not found"
    exit 2
fi

echo "Attaching gdbserver to main PID=$PID on TCP/$PORT"
echo "Host: gdb-multiarch -> target remote CAMERA_IP:$PORT"
exec "$GDBSERVER" "0.0.0.0:$PORT" --attach "$PID"
