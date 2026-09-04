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

echo "[+] Installing RF base tools"
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg iw usbutils iproute2 pciutils kmod procps

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "[+] Installing Docker Engine from Docker's official Ubuntu repository"
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc

  ARCH="$(dpkg --print-architecture)"
  CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
  if [[ -z "$CODENAME" ]]; then
    echo "[-] Could not determine Ubuntu codename." >&2
    exit 1
  fi

  sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $CODENAME
Components: stable
Architectures: $ARCH
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  echo "[+] Docker Engine/Compose already present"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
  sudo systemctl enable --now docker
else
  if ! pgrep -x dockerd >/dev/null 2>&1; then
    echo "[+] Starting dockerd without systemd"
    sudo nohup dockerd >/tmp/dockerd-rf.log 2>&1 &
    for _ in $(seq 1 20); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
  fi
fi

if ! docker info >/dev/null 2>&1; then
  echo "[-] Docker daemon is not reachable." >&2
  echo "[i] Try: sudo service docker start" >&2
  echo "[i] Or inspect: /tmp/dockerd-rf.log" >&2
  exit 1
fi

if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
  echo "[+] Adding $USER to docker group"
  sudo usermod -aG docker "$USER"
  echo "[i] Group membership changes on next WSL login. For this session use sudo docker ..."
fi

echo ""
echo "=== USB visible in this Ubuntu WSL ==="
lsusb || true

echo ""
echo "=== Wireless PHY/interfaces visible in this Ubuntu WSL ==="
iw dev || true
iw phy || true

echo ""
echo "[+] Docker Engine: $(docker --version)"
echo "[+] Compose      : $(docker compose version)"
echo ""
echo "[+] WSL RF environment is ready."
echo "[i] Next Windows step: attach the Alfa USB adapter with scripts/attach-rf-usb.ps1"
echo "[i] Then rerun: lsusb ; iw dev ; iw phy"
