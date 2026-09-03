# Reproduction commands — current firmware/static-analysis milestone

These commands document how the current 1.4.2 analysis was reached. Adjust paths if the local project directory differs.

```powershell
python .\v5patchlab.py public-base-info
python .\v5patchlab.py public-base-fetch
python .\v5patchlab.py magic-scan .\firmware\Tapo_C200v5_1.4.2_260513.bin
python .\v5patchlab.py decryptor-check
python .\v5patchlab.py wsl-path-check .\firmware\Tapo_C200v5_1.4.2_260513.bin
python .\v5patchlab.py decrypt .\firmware\Tapo_C200v5_1.4.2_260513.bin
python .\v5patchlab.py magic-scan .\firmware\Tapo_C200v5_1.4.2_260513.bin.dec
python .\v5patchlab.py extract .\firmware\Tapo_C200v5_1.4.2_260513.bin.dec --out .\analysis\c200v5-142
python .\v5patchlab.py find-main .\analysis\c200v5-142
```

Copy the recovered `squashfs-root/bin/main` to a stable evidence path before reverse engineering, then record its SHA-256.

Cross-binutils required for MIPS disassembly under Ubuntu WSL:

```powershell
wsl sudo apt update
wsl sudo apt install -y binutils-mipsel-linux-gnu
```

Representative reverse commands:

```powershell
$MAIN_WSL="/mnt/c/Users/artbo/PycharmProjects/etude-tapoc200-v5/analysis/c200v5-142/main-1.4.2"

wsl bash -lc "readelf -h '$MAIN_WSL'"
wsl bash -lc "readelf -SW '$MAIN_WSL'"
wsl bash -lc "readelf -sW '$MAIN_WSL' | grep -Ei 'spake|rtsp|decrypt|auth'"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$MAIN_WSL' --start-address=0x4cef98 --stop-address=0x4cf104"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$MAIN_WSL' --start-address=0x4d0640 --stop-address=0x4d0788"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$MAIN_WSL' --start-address=0x4d3098 --stop-address=0x4d30f4"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$MAIN_WSL' --start-address=0x4d194c --stop-address=0x4d19b8"
```

S1-focused static map added in v1.0.15:

```powershell
python .\v5patchlab.py s1-static-map `
  .\analysis\c200v5-142\main-1.4.2 `
  --rootfs .\analysis\c200v5-142\_Tapo_C200v5_1.4.2_260513.bin.dec-0.extracted\squashfs-root `
  --xrefs `
  --out .\analysis\s1-static-map
```
