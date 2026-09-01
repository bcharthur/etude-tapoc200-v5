from __future__ import annotations

FLASH_SIZE = 0x800000

PARTITIONS = {
    "factory_boot": (0x000000, 0x02D800),
    "factory_info": (0x02D800, 0x030000),
    "art":          (0x030000, 0x040000),
    "config":       (0x040000, 0x050000),
    "normal_boot":  (0x050000, 0x070000),
    "kernel":       (0x070200, 0x1B0000),
    "rootfs":       (0x1B0000, 0x3D0000),
    "rootfs_data":  (0x3D0000, 0x770000),
    "user_record":  (0x770000, 0x7F0000),
    "verify":       (0x7F0000, 0x800000),
    "firmware":     (0x070000, 0x770000),
}

ROOTFS_START, ROOTFS_END = PARTITIONS["rootfs"]
ROOTFS_SIZE = ROOTFS_END - ROOTFS_START

ROOTFS_IV = bytes.fromhex("55aadeadc0de4c494e5558457854aa55")
