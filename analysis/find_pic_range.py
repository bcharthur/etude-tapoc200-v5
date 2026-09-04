import re
import subprocess
import sys

main = sys.argv[1]
lo = int(sys.argv[2], 16)
hi = int(sys.argv[3], 16)

out = subprocess.check_output(
    ["wsl", "mipsel-linux-gnu-objdump", "-d", main],
    text=True,
    errors="replace"
)

lines = out.splitlines()

lui_re = re.compile(
    r"^\s*([0-9a-f]+):.*\blui\s+(\w+),0x([0-9a-f]+)"
)

addiu_re = re.compile(
    r"^\s*([0-9a-f]+):.*\baddiu\s+(\w+),(\w+),(-?\d+)"
)

mem_re = re.compile(
    r"^\s*([0-9a-f]+):.*\b(?:lw|sw|lh|lhu|sh|lb|lbu|sb)\s+\w+,(-?\d+)\((\w+)\)"
)

for i, line in enumerate(lines):
    m = lui_re.search(line)
    if not m:
        continue

    reg = m.group(2)
    base = int(m.group(3), 16) << 16

    for j in range(i + 1, min(i + 14, len(lines))):
        a = addiu_re.search(lines[j])
        if a and a.group(2) == reg and a.group(3) == reg:
            value = (base + int(a.group(4))) & 0xffffffff

            if lo <= value < hi:
                print(f"\n=== 0x{value:08x} ===")
                for k in range(max(0, i - 8), min(len(lines), j + 25)):
                    print(lines[k])

        m2 = mem_re.search(lines[j])
        if m2 and m2.group(3) == reg:
            value = (base + int(m2.group(2))) & 0xffffffff

            if lo <= value < hi:
                print(f"\n=== MEM 0x{value:08x} ===")
                for k in range(max(0, i - 8), min(len(lines), j + 25)):
                    print(lines[k])
