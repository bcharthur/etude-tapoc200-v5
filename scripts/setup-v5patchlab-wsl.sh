#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

echo "[1/5] Installing base build/extraction tools"
sudo apt update
sudo apt install -y \
  git build-essential libssl-dev \
  binwalk squashfs-tools file xz-utils \
  python3-pip python3-venv pipx \
  liblzo2-dev mtd-utils wget xxd

echo "[2/5] Installing binwalk external filesystem extractors"
pipx ensurepath >/dev/null 2>&1 || true
export PATH="$HOME/.local/bin:$PATH"

install_pipx_if_missing() {
  cmd="$1"
  package="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Installing $package with pipx..."
    pipx install "$package"
  fi
}

install_pipx_if_missing jefferson jefferson
install_pipx_if_missing ubireader_extract_files ubi-reader

export PATH="$HOME/.local/bin:$PATH"

echo "  binwalk:                 $(command -v binwalk || true)"
echo "  jefferson:               $(command -v jefferson || true)"
echo "  ubireader_extract_files: $(command -v ubireader_extract_files || true)"

for cmd in binwalk jefferson ubireader_extract_files; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required extractor unavailable: $cmd"
    exit 2
  fi
done

echo "[3/5] Cloning/updating tp-link-decrypt"
cd "$HOME"
if [ -d tp-link-decrypt/.git ]; then
  cd tp-link-decrypt
  git pull --ff-only
else
  git clone https://github.com/robbins/tp-link-decrypt
  cd tp-link-decrypt
fi

echo "[4/5] Extracting TP-Link-published keys non-interactively"
rm -rf include tmp.fwextract
mkdir -p include

set +e
printf 'yes\n' | ./extract_keys.sh
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  echo ""
  echo "ERROR: upstream extract_keys.sh failed (rc=$rc)."
  echo "Run these diagnostics in Ubuntu:"
  echo "  command -v jefferson"
  echo "  command -v ubireader_extract_files"
  echo "  find \"$HOME/tp-link-decrypt/tmp.fwextract\" -type f \\"
  echo "    \\( -name nvrammanager -o -name slpupgrade \\) -print"
  echo "  tail -n 160 \"$HOME/tp-link-decrypt/tmp.fwextract/rsa_key_extractor.log\""
  exit 3
fi

for f in include/RSA_0.h include/RSA_1.h include/DES_KEY.h include/DES_IV.h; do
  if [ ! -s "$f" ]; then
    echo "ERROR: expected generated include missing/empty: $f"
    exit 4
  fi
done

echo "[5/5] Building tp-link-decrypt"
make clean >/dev/null 2>&1 || true
make

if [ ! -x bin/tp-link-decrypt ]; then
  echo "ERROR: build did not produce bin/tp-link-decrypt"
  exit 5
fi

echo ""
echo "READY"
echo "  decryptor: $HOME/tp-link-decrypt/bin/tp-link-decrypt"
echo "  jefferson: $(command -v jefferson)"
echo "  ubi_reader: $(command -v ubireader_extract_files)"
