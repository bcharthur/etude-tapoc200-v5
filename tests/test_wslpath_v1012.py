from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.wsl import _manual_windows_to_wsl

assert _manual_windows_to_wsl(
    r"C:\Users\artbo\PycharmProjects\etude-tapoc200-v5\firmware\x.bin"
) == "/mnt/c/Users/artbo/PycharmProjects/etude-tapoc200-v5/firmware/x.bin"
assert _manual_windows_to_wsl(r"D:\A B\c.bin") == "/mnt/d/A B/c.bin"
assert _manual_windows_to_wsl("/tmp/a") is None

print("v1.0.12 WSL path synthetic self-test: OK")
