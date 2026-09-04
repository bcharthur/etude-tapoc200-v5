from pathlib import Path
from elftools.elf.elffile import ELFFile
import struct
import sys

path = Path(sys.argv[1])
target = int(sys.argv[2], 16)

blob = path.read_bytes()
needle = struct.pack("<I", target)

with path.open("rb") as f:
    elf = ELFFile(f)

    pos = 0

    while True:
        off = blob.find(needle, pos)
        if off < 0:
            break

        sec_name = "???"
        va = None

        for sec in elf.iter_sections():
            so = sec["sh_offset"]
            ss = sec["sh_size"]

            if so <= off < so + ss:
                sec_name = sec.name
                va = sec["sh_addr"] + off - so
                break

        print(
            f"target=0x{target:x} "
            f"file_off=0x{off:x} "
            f"va={hex(va) if va is not None else '???'} "
            f"section={sec_name}"
        )

        pos = off + 1
