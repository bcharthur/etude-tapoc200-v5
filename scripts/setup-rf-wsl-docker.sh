#!/usr/bin/env bash
set -euo pipefail

if ! grep -qi microsoft /proc/version; then
  echo "[-] This helper is intended for Ubuntu running under WSL2." >&2
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "[-] /etc/os-release missing." >&2
  exit 1
fi

. /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "[-] Expected Ubuntu WSL, got ID=${ID:-unknown}." >&2
  exit 1
fi

echo "[+] WSL kernel: $(uname -r)"
echo "[+] Ubuntu: ${PRETTY_NAME:-unknown}"

echo "[+] Installing RF base tools and a local Docker daemon"
sudo apt-get update
sudo apt-get install -y \
  ca-certificates curl gnupg iw usbutils iproute2 pciutils kmod procps \
  docker.io docker-compose-v2

if ! command -v dockerd >/dev/null 2>&1; then
  echo "[-] dockerd is still missing after package installation." >&2
  exit 1
fi

RF_SOCKET="/var/run/docker-rf.sock"
RF_DATA_ROOT="/var/lib/docker-rf"
RF_EXEC_ROOT="/var/run/docker-rf"
RF_PIDFILE="/run/docker-rf.pid"
RF_CONTEXT="rf-wsl"

# Docker Desktop may inject a Docker CLI/context into WSL. Never reuse its
# daemon/socket for the RF lab. Run a second, explicit dockerd on its own socket.
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
  echo "[+] Installing docker-rf systemd service"
  sudo tee /etc/systemd/system/docker-rf.service >/dev/null <<EOF
[Unit]
Description=Local Docker daemon for Tapo RF lab
After=network.target

[Service]
Type=notify
ExecStart=/usr/bin/dockerd --host=unix://$RF_SOCKET --data-root=$RF_DATA_ROOT --exec-root=$RF_EXEC_ROOT --pidfile=$RF_PIDFILE
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutStartSec=0
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now docker-rf
else
  echo "[+] systemd unavailable; starting dedicated dockerd in background"
  if [[ -f "$RF_PIDFILE" ]]; then
    oldpid="$(cat "$RF_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$oldpid" ]] && kill -0 "$oldpid" 2>/dev/null; then
      echo "[+] docker-rf already running as PID $oldpid"
    else
      sudo rm -f "$RF_PIDFILE"
    fi
  fi

  if [[ ! -S "$RF_SOCKET" ]]; then
    sudo nohup /usr/bin/dockerd \
      --host="unix://$RF_SOCKET" \
      --data-root="$RF_DATA_ROOT" \
      --exec-root="$RF_EXEC_ROOT" \
      --pidfile="$RF_PIDFILE" \
      >/tmp/dockerd-rf.log 2>&1 &
  fi
fi

for _ in $(seq 1 30); do
  if sudo docker --host "unix://$RF_SOCKET" info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! sudo docker --host "unix://$RF_SOCKET" info >/dev/null 2>&1; then
  echo "[-] Dedicated RF Docker daemon is not reachable on $RF_SOCKET." >&2
  if command -v systemctl >/dev/null 2>&1; then
    echo "[i] Inspect: sudo systemctl status docker-rf --no-pager" >&2
    echo "[i] Logs   : sudo journalctl -u docker-rf -n 100 --no-pager" >&2
  fi
  echo "[i] Fallback log: /tmp/dockerd-rf.log" >&2
  exit 1
fi

# Allow the normal user to access the dedicated socket through the docker group.
if ! getent group docker >/dev/null; then
  sudo groupadd docker
fi
if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
  echo "[+] Adding $USER to docker group"
  sudo usermod -aG docker "$USER"
fi
sudo chgrp docker "$RF_SOCKET"
sudo chmod 660 "$RF_SOCKET"

# Create a context that cannot accidentally fall back to Docker Desktop.
if docker context inspect "$RF_CONTEXT" >/dev/null 2>&1; then
  docker context rm -f "$RF_CONTEXT" >/dev/null 2>&1 || true
fi
docker context create "$RF_CONTEXT" --docker "host=unix://$RF_SOCKET" >/dev/null

echo ""
echo "=== Docker separation check ==="
echo "Desktop/current CLI target:"
docker info --format '  Name={{.Name}} OS={{.OperatingSystem}} Kernel={{.KernelVersion}}' 2>/dev/null || echo "  unavailable"
echo "Dedicated RF daemon:"
docker --context "$RF_CONTEXT" info --format '  Name={{.Name}} OS={{.OperatingSystem}} Kernel={{.KernelVersion}}'

echo ""
echo "=== USB visible in this Ubuntu WSL ==="
lsusb || true

echo ""
echo "=== Wireless PHY/interfaces visible in this Ubuntu WSL ==="
iw dev || true
iw phy || true

echo ""
echo "[+] RF Docker context is ready: $RF_CONTEXT"
echo "[i] Use it explicitly: docker --context $RF_CONTEXT compose -f docker-compose.rf.yml build"
echo "[i] Then:             docker --context $RF_CONTEXT compose -f docker-compose.rf.yml run --rm rf probe"
echo ""
echo "[i] The Alfa USB adapter is a separate prerequisite."
echo "[i] On Windows, run usbipd list and use the BUSID actually shown for the Alfa."
