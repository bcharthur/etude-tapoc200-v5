#!/usr/bin/env bash
set -euo pipefail

CAMERA_MAC="${CAMERA_MAC:-dc:62:79:8b:3a:da}"
WIFI_IFACE="${WIFI_IFACE:-}"
MON_IFACE="${MON_IFACE:-mon0}"
CHANNEL="${CHANNEL:-}"
AP_BSSID="${AP_BSSID:-}"
COUNT="${COUNT:-1}"
OBSERVE_SECONDS="${OBSERVE_SECONDS:-45}"

usage() {
  cat <<'EOF'
Tapo C200 S1 RF container

Native Linux host only. Docker Desktop/WSL cannot expose an internal PCIe Wi-Fi
adapter to this container in monitor mode.

Commands:
  rf-lab probe
  rf-lab observe --channel 6
  rf-lab deauth --channel 6 --ap-bssid aa:bb:cc:dd:ee:ff [--count 1]
  rf-lab disassoc --channel 6 --ap-bssid aa:bb:cc:dd:ee:ff [--count 1]

Options:
  --wifi <iface>          managed RZ608 interface; auto-detected when possible
  --monitor <iface>       monitor VIF name (default mon0)
  --channel <n>           target AP channel
  --camera-mac <mac>      default dc:62:79:8b:3a:da
  --ap-bssid <mac>        legitimate AP BSSID
  --count <1..3>          bounded injection count, default 1
  --observe-seconds <n>   10..300, default 45
EOF
}

MODE="${1:-probe}"
if [[ $# -gt 0 ]]; then shift; fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wifi) WIFI_IFACE="$2"; shift 2 ;;
    --monitor) MON_IFACE="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --camera-mac) CAMERA_MAC="$2"; shift 2 ;;
    --ap-bssid) AP_BSSID="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --observe-seconds) OBSERVE_SECONDS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[-] Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$MODE" =~ ^(probe|observe|deauth|disassoc)$ ]] || { echo "[-] Invalid command: $MODE" >&2; usage; exit 2; }
[[ "$COUNT" =~ ^[1-3]$ ]] || { echo "[-] --count must be 1..3" >&2; exit 2; }
[[ "$OBSERVE_SECONDS" =~ ^[0-9]+$ ]] && (( OBSERVE_SECONDS >= 10 && OBSERVE_SECONDS <= 300 )) || { echo "[-] --observe-seconds must be 10..300" >&2; exit 2; }
[[ "$CAMERA_MAC" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || { echo "[-] Invalid camera MAC" >&2; exit 2; }

# Identify the RZ608/MT7921E interface first, then fall back to the first Wi-Fi VIF.
if [[ -z "$WIFI_IFACE" ]]; then
  for p in /sys/class/net/*; do
    [[ -e "$p/device/driver" ]] || continue
    drv="$(basename "$(readlink -f "$p/device/driver" 2>/dev/null || true)")"
    if [[ "$drv" == "mt7921e" ]]; then
      WIFI_IFACE="$(basename "$p")"
      break
    fi
  done
fi
if [[ -z "$WIFI_IFACE" ]]; then
  WIFI_IFACE="$(iw dev | awk '$1=="Interface" {print $2; exit}')"
fi
[[ -n "$WIFI_IFACE" ]] || { echo "[-] No Wi-Fi interface visible in the container." >&2; exit 1; }

PHY="$(iw dev "$WIFI_IFACE" info | awk '$1=="wiphy" {print "phy"$2; exit}')"
[[ -n "$PHY" ]] || { echo "[-] Could not resolve PHY for $WIFI_IFACE" >&2; exit 1; }
DRIVER="$(basename "$(readlink -f "/sys/class/net/$WIFI_IFACE/device/driver" 2>/dev/null || true)")"

echo "[+] Default route   : $(ip route show default | head -n1 || true)"
echo "[+] Wi-Fi interface: $WIFI_IFACE"
echo "[+] Driver         : ${DRIVER:-unknown}"
echo "[+] PHY            : $PHY"
echo ""

echo "=== PCI wireless hardware ==="
lspci -nnk | grep -A3 -Ei 'network controller|wireless' || true
echo ""
echo "=== Supported interface modes ==="
MODES="$(iw phy "$PHY" info | sed -n '/Supported interface modes:/,/Band [0-9]/p' | head -n 50)"
printf '%s\n' "$MODES"

if ! printf '%s\n' "$MODES" | grep -Eq '^\s*\* monitor\s*$'; then
  echo "[-] $PHY does not advertise monitor mode." >&2
  exit 1
fi

if [[ "$MODE" == "probe" ]]; then
  echo ""
  echo "[+] monitor mode advertised: YES"
  if [[ "$DRIVER" == "mt7921e" ]]; then
    echo "[+] RZ608 / MT7921E detected."
  fi
  echo "[i] Next: docker compose -f docker-compose.rf.yml run --rm rf observe --channel <AP_CHANNEL>"
  exit 0
fi

[[ "$CHANNEL" =~ ^[0-9]+$ ]] && (( CHANNEL >= 1 && CHANNEL <= 196 )) || { echo "[-] --channel is required (1..196)" >&2; exit 2; }
if [[ "$MODE" =~ ^(deauth|disassoc)$ ]]; then
  [[ "$AP_BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || { echo "[-] --ap-bssid is required and must be a MAC address" >&2; exit 2; }
fi

cleanup() {
  if iw dev "$MON_IFACE" info >/dev/null 2>&1; then
    echo "[+] Removing monitor VIF $MON_IFACE"
    iw dev "$MON_IFACE" del || true
  fi
}
trap cleanup EXIT INT TERM

# Do not convert the Windows/Linux managed interface in-place. Create a separate
# monitor VIF on the same PHY so Ethernet remains the host's Internet path.
if iw dev "$MON_IFACE" info >/dev/null 2>&1; then
  iw dev "$MON_IFACE" del
fi

echo "[+] Creating monitor VIF $MON_IFACE on $PHY"
iw phy "$PHY" interface add "$MON_IFACE" type monitor
ip link set "$MON_IFACE" up
iw dev "$MON_IFACE" set channel "$CHANNEL"

echo "[+] Monitor interface ready"
iw dev "$MON_IFACE" info

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/lab/evidence/runs/${STAMP}-s1-rf-docker-${MODE}"
mkdir -p "$OUT"

ARGS=(
  python3 /lab/scripts/s1_rf_trial.py
  --iface "$MON_IFACE"
  --camera-mac "$CAMERA_MAC"
  --action "$MODE"
  --count "$COUNT"
  --observe-seconds "$OBSERVE_SECONDS"
  --out "$OUT"
)
if [[ "$MODE" =~ ^(deauth|disassoc)$ ]]; then
  ARGS+=(--ap-bssid "$AP_BSSID")
fi

echo "[+] Starting bounded trial: mode=$MODE count=$COUNT channel=$CHANNEL"
"${ARGS[@]}"
echo "[+] Evidence: $OUT"
