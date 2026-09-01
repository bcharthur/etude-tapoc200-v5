from __future__ import annotations

import getpass
import os
import shutil
import subprocess
from pathlib import Path

from .crypto import md5crypt


def _run(cmd):
    cp = subprocess.run(cmd, text=True, capture_output=True)
    if cp.returncode != 0:
        raise RuntimeError(
            f"Command failed ({cp.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )
    return cp


def _wsl_path(path: str | Path) -> str:
    p = str(Path(path).resolve())
    cp = _run(["wsl.exe", "wslpath", "-a", p])
    return cp.stdout.strip()


def _tool(name: str) -> tuple[list[str], str]:
    if shutil.which(name):
        return [name], "native"
    if shutil.which("wsl.exe"):
        cp = subprocess.run(
            ["wsl.exe", "sh", "-lc", f"command -v {name}"],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return ["wsl.exe", name], "wsl"
    raise RuntimeError(
        f"Required tool '{name}' not found natively or in WSL. "
        "Install squashfs-tools in WSL."
    )


def extract_squashfs(image: str | Path, out_dir: str | Path) -> dict:
    image = Path(image).resolve()
    out = Path(out_dir).resolve()
    if out.exists() and any(out.iterdir()):
        raise RuntimeError(f"Output directory is not empty: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)

    prefix, mode = _tool("unsquashfs")
    if mode == "native":
        _run(prefix + ["-d", str(out), str(image)])
    else:
        wi = _wsl_path(image)
        wo = _wsl_path(out)
        _run(prefix + ["-d", wo, wi])

    return {
        "image": str(image),
        "tree": str(out),
        "mode": mode,
    }


def repack_squashfs(tree: str | Path, output: str | Path) -> dict:
    tree = Path(tree).resolve()
    out = Path(output).resolve()
    if not tree.is_dir():
        raise RuntimeError(f"Rootfs tree not found: {tree}")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    prefix, mode = _tool("mksquashfs")
    common = ["-noappend", "-comp", "xz", "-b", "65536"]

    if mode == "native":
        _run(prefix + [str(tree), str(out)] + common)
    else:
        wt = _wsl_path(tree)
        wo = _wsl_path(out)
        _run(prefix + [wt, wo] + common)

    return {
        "tree": str(tree),
        "output": str(out),
        "size": out.stat().st_size,
        "mode": mode,
    }


def patch_shadow(tree: str | Path, password: str | None = None) -> dict:
    tree = Path(tree)
    shadow = tree / "etc/shadow"
    if not shadow.exists():
        raise FileNotFoundError(f"No /etc/shadow in rootfs tree: {shadow}")

    if password is None:
        password = getpass.getpass("New LAB root password: ")
        confirm = getpass.getpass("Confirm LAB root password: ")
        if password != confirm:
            raise RuntimeError("Passwords do not match")
    if len(password) < 8:
        raise RuntimeError("Use at least 8 characters for the lab root password")

    salt_hash = md5crypt(password)
    lines = shadow.read_text(encoding="utf-8", errors="replace").splitlines()
    changed = False
    new_lines = []

    for line in lines:
        parts = line.split(":")
        if parts and parts[0] == "root":
            while len(parts) < 2:
                parts.append("")
            parts[1] = salt_hash
            line = ":".join(parts)
            changed = True
        new_lines.append(line)

    if not changed:
        raise RuntimeError("No root entry found in /etc/shadow")

    backup = shadow.with_name("shadow.rootlab-original")
    if not backup.exists():
        shutil.copy2(shadow, backup)

    shadow.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return {
        "shadow": str(shadow),
        "backup": str(backup),
        "root_password_hash_scheme": "md5-crypt",
        "password_saved_plaintext": False,
    }


def _elf_mips_le(path: Path) -> tuple[bool, str]:
    data = path.read_bytes()[:64]
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return False, "not-elf"
    endian = data[5]
    little = endian == 1
    machine = int.from_bytes(data[18:20], "little" if little else "big")
    return little and machine == 8, f"ELF machine={machine} little={little}"


def inject_bundle(
    tree: str | Path,
    bundle_dir: str | Path,
    tool_dir: str | Path | None = None,
) -> dict:
    tree = Path(tree)
    dest = tree / "opt/rootlab"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(bundle_dir, dest)

    injected_tools = []
    warnings = []
    if tool_dir:
        src = Path(tool_dir)
        if not src.is_dir():
            raise RuntimeError(f"Tool directory not found: {src}")
        bindir = dest / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        for p in sorted(src.iterdir()):
            if not p.is_file():
                continue
            target = bindir / p.name
            shutil.copy2(p, target)
            target.chmod(0o755)
            ok, desc = _elf_mips_le(target)
            injected_tools.append({
                "name": p.name,
                "mips_little_endian": ok,
                "description": desc,
            })
            if not ok:
                warnings.append(f"{p.name}: {desc}")

    for p in dest.rglob("*.sh"):
        p.chmod(0o755)

    return {
        "destination": str(dest),
        "tools": injected_tools,
        "warnings": warnings,
    }
