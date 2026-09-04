from __future__ import annotations

import os
import shlex
from pathlib import Path

from .evidence import sha256_file
from .wsl import run_wsl, wsl_path, command_exists


MAGICS = {
    "uimage": bytes.fromhex("27051956"),
    "squashfs_le": b"hsqs",
    "squashfs_be": b"sqsh",
    "xz": bytes.fromhex("fd377a585a00"),
    "gzip": bytes.fromhex("1f8b08"),
    "elf": b"\x7fELF",
}


def magic_scan(path: str | Path, max_hits_per_magic=100) -> dict:
    p = Path(path)
    data = p.read_bytes()
    hits = {}

    for name, magic in MAGICS.items():
        offsets = []
        start = 0
        while True:
            pos = data.find(magic, start)
            if pos < 0:
                break
            offsets.append(pos)
            start = pos + 1
            if len(offsets) >= max_hits_per_magic:
                break
        if offsets:
            hits[name] = offsets

    return {
        "path": str(p),
        "size": len(data),
        "sha256": sha256_file(p),
        "magic_hits": hits,
    }


def _safe_tree_inventory(root: str | Path) -> dict:
    """
    Enumerate regular files without following firmware symlinks.

    SquashFS root filesystems commonly contain BusyBox symlinks such as
    /bin/dmesg -> busybox.  When unsquashfs/binwalk creates those links on
    a Windows-mounted WSL path, Windows may expose them as reparse points
    which raise WinError 1920 on Path.is_file()/Path.stat().

    os.walk(..., followlinks=False) plus explicit symlink skipping prevents
    one such entry from aborting the whole firmware extraction workflow.
    """
    root = Path(root)
    files = []
    skipped = []
    walk_errors = []

    def onerror(exc):
        walk_errors.append({
            "path": getattr(exc, "filename", None),
            "error": f"{type(exc).__name__}: {exc}",
        })

    for dirpath, dirnames, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        # Do not descend into directory symlinks/reparse points.
        kept_dirs = []
        for name in dirnames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    skipped.append({
                        "path": str(p),
                        "reason": "directory-symlink",
                    })
                    continue
            except OSError as exc:
                skipped.append({
                    "path": str(p),
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    skipped.append({
                        "path": str(p),
                        "reason": "file-symlink",
                    })
                    continue
                st = p.stat()
            except OSError as exc:
                skipped.append({
                    "path": str(p),
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue

            files.append({
                "path": str(p),
                "size": st.st_size,
            })

    return {
        "files": files,
        "file_count": len(files),
        "skipped_entries": skipped,
        "skipped_entry_count": len(skipped),
        "walk_errors": walk_errors,
        "walk_error_count": len(walk_errors),
    }


def binwalk_extract(
    image: str | Path,
    out_dir: str | Path,
) -> dict:
    if not command_exists("binwalk"):
        raise RuntimeError(
            "binwalk not installed in default WSL distro. "
            "Install it or use magic-scan first."
        )

    image = Path(image).resolve()
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    wi = wsl_path(image)
    wo = wsl_path(out)

    # Work inside requested output directory. Binwalk creates its own
    # extraction directory under CWD; preserve it for reproducibility.
    cp = run_wsl(
        f"cd {shlex.quote(wo)} && "
        f"binwalk -eM {shlex.quote(wi)}"
    )

    inventory = _safe_tree_inventory(out)

    return {
        "image": str(image),
        "output_dir": str(out),
        "extraction_command_completed": True,
        "files": inventory["files"][:5000],
        "file_count": inventory["file_count"],
        "skipped_entries": inventory["skipped_entries"][:200],
        "skipped_entry_count": inventory["skipped_entry_count"],
        "walk_errors": inventory["walk_errors"][:100],
        "walk_error_count": inventory["walk_error_count"],
        "stdout": cp.stdout[-12000:],
        "note": (
            "SquashFS symlinks/reparse points are intentionally skipped "
            "during the Windows-side inventory. They remain in the "
            "extracted filesystem and do not indicate extraction failure."
        ),
    }


def _candidate_rows(root: str | Path) -> tuple[list[dict], list[dict], list[dict]]:
    root = Path(root)
    if not root.is_dir():
        raise RuntimeError(f"Directory not found: {root}")

    anchors = [
        b"device_confirm",
        b"pake_register",
        b"pake_share",
        b"ciphertext",
        b"securePassthrough",
        b"third_account",
        b"changeThirdAccount",
        b"/stream",
        b"ONVIF",
    ]

    rows = []
    skipped = []
    walk_errors = []

    def onerror(exc):
        walk_errors.append({
            "path": getattr(exc, "filename", None),
            "error": f"{type(exc).__name__}: {exc}",
        })

    for dirpath, dirnames, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        kept_dirs = []
        for name in dirnames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    skipped.append({
                        "path": str(p),
                        "reason": "directory-symlink",
                    })
                    continue
            except OSError as exc:
                skipped.append({
                    "path": str(p),
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in filenames:
            p = Path(dirpath) / name

            try:
                if p.is_symlink():
                    skipped.append({
                        "path": str(p),
                        "reason": "file-symlink",
                    })
                    continue
                size = p.stat().st_size
            except OSError as exc:
                skipped.append({
                    "path": str(p),
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue

            if size < 50_000 or size > 100_000_000:
                continue

            score = 0
            namescore = 0
            if p.name == "main":
                namescore = 100
            elif p.name in ("tp_manage", "camera", "ipc"):
                namescore = 40

            try:
                with p.open("rb") as f:
                    head = f.read(4)
                is_elf = head == b"\x7fELF"
                if not is_elf and not namescore:
                    continue
                data = p.read_bytes()
            except OSError as exc:
                skipped.append({
                    "path": str(p),
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                continue

            matched = []
            for anchor in anchors:
                if anchor in data:
                    matched.append(anchor.decode("ascii"))
                    score += 10

            score += namescore
            if score:
                try:
                    digest = sha256_file(p)
                except OSError as exc:
                    skipped.append({
                        "path": str(p),
                        "reason": f"sha256:{type(exc).__name__}: {exc}",
                    })
                    digest = None

                rows.append({
                    "path": str(p),
                    "size": size,
                    "sha256": digest,
                    "score": score,
                    "anchors": matched,
                })

    rows.sort(key=lambda r: (-r["score"], -r["size"]))
    return rows, skipped, walk_errors


def find_main_candidates(root: str | Path) -> list[dict]:
    rows, _, _ = _candidate_rows(root)
    return rows


def find_main_report(root: str | Path) -> dict:
    rows, skipped, walk_errors = _candidate_rows(root)
    return {
        "root": str(Path(root)),
        "candidates": rows,
        "candidate_count": len(rows),
        "skipped_entries": skipped[:200],
        "skipped_entry_count": len(skipped),
        "walk_errors": walk_errors[:100],
        "walk_error_count": len(walk_errors),
        "interpretation": {
            "symlink_skip_expected": True,
            "note": (
                "BusyBox/rootfs symlinks such as bin/dmesg may be "
                "inaccessible from Windows after WSL extraction. They are "
                "skipped rather than treated as extraction failure."
            ),
        },
    }
