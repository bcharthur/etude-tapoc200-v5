from pathlib import Path
from elftools.elf.elffile import ELFFile
import sys
import struct

path = Path(sys.argv[1])
needle = sys.argv[2].encode() + b"\x00"

with path.open("rb") as f:
    blob = f.read()

with path.open("rb") as f:
    elf = ELFFile(f)

    hits = []
    start = 0

    while True:
        off = blob.find(needle, start)
        if off < 0:
            break

        va = None
        section_name = None

        for sec in elf.iter_sections():
            sh_off = sec["sh_offset"]
            sh_size = sec["sh_size"]

            if sh_off <= off < sh_off + sh_size:
                va = sec["sh_addr"] + (off - sh_off)
                section_name = sec.name
                break

        hits.append((off, va, section_name))
        start = off + 1

    for off, va, sec in hits:
        print(
            f"file_off=0x{off:x} "
            f"va={('0x%x' % va) if va is not None else '???'} "
            f"section={sec}"
        )

        if va is not None:
            packed = struct.pack("<I", va)

            p = 0
            while True:
                x = blob.find(packed, p)
                if x < 0:
                    break
                print(f"  pointer-to-string @ file_off=0x{x:x}")
                p = x + 1
