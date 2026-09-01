from __future__ import annotations

import argparse
import getpass
import json
import shutil
from pathlib import Path

from .evidence import sha256_file, write_json
from .flash import (
    validate_dump,
    carve,
    decrypt_rootfs,
    build_flash_image,
)
from .gdb import generate_gdb_dump_script
from .layout import FLASH_SIZE, PARTITIONS
from .ram import generate_ram_script
from .rootfs import (
    extract_squashfs,
    repack_squashfs,
    patch_shadow,
    inject_bundle,
)
from .serialio import list_ports, miniterm, capture
from .uimage import inspect_kernel


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEVICE_BUNDLE = PACKAGE_ROOT / "device"


def emit(data):
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def cmd_plan(args):
    emit({
        "phase_0": "Connect verified-logic-level USB-TTL to C200 V5 UART.",
        "phase_1": "Interrupt U-Boot with slp and acquire exact 8 MiB NOR backup.",
        "phase_2": "Validate/carve dump; auto-extract rootfs AES key from kernel.",
        "phase_3": "Decrypt/extract SquashFS, set LAB root password, inject RootLab scripts/tools.",
        "phase_4": "Repack and build rooted flash image; preserve original backup.",
        "phase_5": "Manually flash through U-Boot only after reviewing hashes/recovery.",
        "phase_6": "Login root over UART and collect /proc, MTD and process state.",
        "phase_7": "Attach strace/gdbserver to main; capture physical RESET transition.",
        "phase_8": "Generate targeted process-memory or System-RAM dumps; diff offline.",
        "phase_9": "Optional Volatility/custom Linux memory analysis if exact symbols can be built.",
    })
    return 0


def cmd_serial_list(args):
    emit({"ports": list_ports()})
    return 0


def cmd_console(args):
    return miniterm(args.port, args.baud)


def cmd_uart_capture(args):
    emit(capture(args.port, args.baud, args.seconds, args.out))
    return 0


def cmd_uboot_dump_plan(args):
    print("""# At U-Boot (interrupt boot by typing: slp)
# READ-ONLY acquisition from SPI NOR into RAM, then SD card.
sf probe
sf read 0x80600000 0x0 0x000000800000
mmc write 0x80600000 0 16384

# Then remove the SD card and acquire exactly 8 MiB on your host.
# Linux/WSL example (REPLACE /dev/mmcblk0 only after verifying the device):
# sudo dd if=/dev/mmcblk0 of=dump.bin bs=1024 count=8192 status=progress
# sha256sum dump.bin
""")
    return 0


def cmd_dump_info(args):
    emit(validate_dump(args.dump))
    return 0


def cmd_carve(args):
    emit(carve(args.dump, args.out))
    return 0


def cmd_kernel_info(args):
    emit(inspect_kernel(args.kernel))
    return 0


def cmd_decrypt_rootfs(args):
    emit(decrypt_rootfs(
        args.dump,
        args.out,
        key_ascii=args.key_ascii,
        key_hex=args.key_hex,
    ))
    return 0


def cmd_extract_rootfs(args):
    emit(extract_squashfs(args.image, args.out))
    return 0


def cmd_patch_rootfs(args):
    tree = Path(args.tree)
    result = {
        "password": patch_shadow(tree, args.password),
        "bundle": inject_bundle(
            tree,
            DEVICE_BUNDLE,
            args.tool_dir,
        ),
    }
    emit(result)
    return 0


def cmd_repack_rootfs(args):
    emit(repack_squashfs(args.tree, args.out))
    return 0


def cmd_build_image(args):
    result = build_flash_image(
        args.original,
        args.rootfs,
        args.out,
        key_ascii=args.key_ascii,
        key_hex=args.key_hex,
    )
    manifest = Path(args.out).with_suffix(Path(args.out).suffix + ".json")
    write_json(manifest, result)
    emit(result)
    return 0


def cmd_flash_plan(args):
    if not args.arm:
        raise RuntimeError(
            "Flash-write plan is hidden unless --arm is supplied. "
            "This command still DOES NOT write hardware."
        )
    info = validate_dump(args.image)
    if not info["size_ok"]:
        raise RuntimeError("Image is not exact 8 MiB")

    print(f"""# REVIEW BEFORE EXECUTION
# image:  {args.image}
# size:   {info['size']} bytes
# sha256: {info['sha256']}
#
# First write this exact 8 MiB image to an SD card on your host.
# Verify the SD contents before placing it in the camera.
#
# U-Boot commands used by the published C200 Rev.5 workflow:
mmc read 0x80600000 0 4000
sf update 0x80600000 0 800000

# Boot kernel:
sf probe
sf read 0x80600000 0x70200 0x200000
bootm 0x80600000

# RECOVERY: keep the untouched original 8 MiB dump and use the same
# mmc read + sf update sequence to restore it if required.
""")
    return 0


def cmd_gdb_script(args):
    emit(generate_gdb_dump_script(
        args.maps,
        args.out,
        remote=args.remote,
        dump_dir=args.dump_dir,
        writable_only=args.writable_only,
        max_region=args.max_region,
    ))
    return 0


def cmd_ram_script(args):
    emit(generate_ram_script(
        args.iomem,
        args.out,
        destination=args.destination,
    ))
    return 0


def cmd_tool_check(args):
    p = Path(args.binary)
    data = p.read_bytes()[:64]
    if len(data) < 20 or data[:4] != b"\\x7fELF":
        emit({"path": str(p), "elf": False})
        return 2
    little = data[5] == 1
    machine = int.from_bytes(data[18:20], "little" if little else "big")
    emit({
        "path": str(p),
        "elf": True,
        "little_endian": little,
        "machine": machine,
        "mips_le": little and machine == 8,
    })
    return 0 if little and machine == 8 else 2


def build_parser():
    p = argparse.ArgumentParser(
        description="TP-Link Tapo C200 V5 hardware/root/memory lab"
    )
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("plan")
    q.set_defaults(func=cmd_plan)

    q = sub.add_parser("serial-list")
    q.set_defaults(func=cmd_serial_list)

    q = sub.add_parser("console")
    q.add_argument("--port", required=True)
    q.add_argument("--baud", type=int, default=115200)
    q.set_defaults(func=cmd_console)

    q = sub.add_parser("uart-capture")
    q.add_argument("--port", required=True)
    q.add_argument("--baud", type=int, default=115200)
    q.add_argument("--seconds", type=int, default=180)
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_uart_capture)

    q = sub.add_parser("uboot-dump-plan")
    q.set_defaults(func=cmd_uboot_dump_plan)

    q = sub.add_parser("dump-info")
    q.add_argument("dump")
    q.set_defaults(func=cmd_dump_info)

    q = sub.add_parser("carve")
    q.add_argument("dump")
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_carve)

    q = sub.add_parser("kernel-info")
    q.add_argument("kernel")
    q.set_defaults(func=cmd_kernel_info)

    q = sub.add_parser("decrypt-rootfs")
    q.add_argument("dump")
    q.add_argument("--out", required=True)
    q.add_argument("--key-ascii", default=None)
    q.add_argument("--key-hex", default=None)
    q.set_defaults(func=cmd_decrypt_rootfs)

    q = sub.add_parser("extract-rootfs")
    q.add_argument("image")
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_extract_rootfs)

    q = sub.add_parser("patch-rootfs")
    q.add_argument("--tree", required=True)
    q.add_argument("--password", default=None)
    q.add_argument(
        "--tool-dir",
        default=None,
        help="Optional directory containing user-supplied MIPSLE static tools "
             "(strace, gdbserver, busybox, etc.)",
    )
    q.set_defaults(func=cmd_patch_rootfs)

    q = sub.add_parser("repack-rootfs")
    q.add_argument("--tree", required=True)
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_repack_rootfs)

    q = sub.add_parser("build-image")
    q.add_argument("--original", required=True)
    q.add_argument("--rootfs", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--key-ascii", default=None)
    q.add_argument("--key-hex", default=None)
    q.set_defaults(func=cmd_build_image)

    q = sub.add_parser("flash-plan")
    q.add_argument("--image", required=True)
    q.add_argument("--arm", action="store_true")
    q.set_defaults(func=cmd_flash_plan)

    q = sub.add_parser("tool-check")
    q.add_argument("binary")
    q.set_defaults(func=cmd_tool_check)

    q = sub.add_parser("gdb-dump-script")
    q.add_argument("--maps", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--remote", default="192.168.1.79:2345")
    q.add_argument("--dump-dir", default="memdump")
    q.add_argument("--writable-only", action="store_true")
    q.add_argument("--max-region", type=int, default=32 * 1024 * 1024)
    q.set_defaults(func=cmd_gdb_script)

    q = sub.add_parser("ram-dump-script")
    q.add_argument("--iomem", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--destination", default="/mnt/sd/rootlab-ram")
    q.set_defaults(func=cmd_ram_script)

    return p


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[rootlab] ERROR: {type(exc).__name__}: {exc}")
        return 2
