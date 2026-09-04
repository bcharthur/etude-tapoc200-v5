from pathlib import Path
import struct

p = Path(r"analysis/c200v5-142/main-1.4.2")
data = p.read_bytes()

targets = {
    "reonboarding": 0x5367E4,
    "ds_module_start": 0x5364D4,
    "reonboarding_rel": 0x1367E4,
    "ds_module_start_rel": 0x1364D4,
}

for name, value in targets.items():
    needle = struct.pack("<I", value)

    start = 0
    found = False

    while True:
        off = data.find(needle, start)
        if off == -1:
            break

        found = True
        print(f"{name:24} file+0x{off:08x} value=0x{value:08x}")
        start = off + 1

    if not found:
        print(f"{name:24} no raw occurrence")