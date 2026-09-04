import re
import subprocess
import sys

main = sys.argv[1]
target = int(sys.argv[2], 16)

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

for i, line in enumerate(lines):
    m = lui_re.search(line)
    if not m:
        continue

    reg = m.group(2)
    hi = int(m.group(3), 16)

    for j in range(i + 1, min(i + 10, len(lines))):
        n = addiu_re.search(lines[j])
        if not n:
            continue

        dst, src = n.group(2), n.group(3)

        if dst != reg or src != reg:
            continue

        imm = int(n.group(4))

        value = ((hi << 16) + imm) & 0xffffffff

        if value == target:
            print("\n=== XREF ===")
            for k in range(max(0, i - 8), min(len(lines), j + 20)):
                print(lines[k])
