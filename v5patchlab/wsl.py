from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


def has_wsl() -> bool:
    return shutil.which("wsl.exe") is not None


def run_wsl(script: str, *, check=True):
    if not has_wsl():
        raise RuntimeError("wsl.exe not found")
    cp = subprocess.run(
        ["wsl.exe", "bash", "-lc", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and cp.returncode != 0:
        raise RuntimeError(
            f"WSL command failed ({cp.returncode})\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )
    return cp


def _manual_windows_to_wsl(p: str) -> str | None:
    # Example: C:\\Users\\alice\\file.bin -> /mnt/c/Users/alice/file.bin
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if not m:
        return None
    drive = m.group(1).lower()
    rest = m.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def wsl_path(path: str | Path) -> str:
    # Use --exec so Windows backslashes are not consumed by a Linux shell.
    if not has_wsl():
        raise RuntimeError("wsl.exe not found")

    p = str(Path(path).resolve())

    attempts = [
        ["wsl.exe", "--exec", "wslpath", "-a", "-u", p],
        ["wsl.exe", "--exec", "wslpath", "-u", p],
    ]

    errors = []
    for argv in attempts:
        cp = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return cp.stdout.strip()
        errors.append({
            "argv": argv[1:],
            "returncode": cp.returncode,
            "stdout": cp.stdout.strip(),
            "stderr": cp.stderr.strip(),
        })

    fallback = _manual_windows_to_wsl(p)
    if fallback:
        cp = subprocess.run(
            ["wsl.exe", "--exec", "test", "-e", fallback],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if cp.returncode == 0:
            return fallback

    raise RuntimeError(
        "Unable to convert Windows path to WSL path.\n"
        f"windows_path={p}\n"
        f"attempts={errors}\n"
        f"fallback={fallback!r}"
    )


def wsl_path_diagnostic(path: str | Path) -> dict:
    resolved = str(Path(path).resolve())
    result = {
        "input": str(path),
        "resolved_windows_path": resolved,
        "contains_backslash": "\\" in resolved,
        "wsl_available": has_wsl(),
        "wsl_path": None,
        "exists_windows": Path(path).exists(),
        "exists_wsl": None,
        "error": None,
    }
    try:
        converted = wsl_path(path)
        result["wsl_path"] = converted
        cp = subprocess.run(
            ["wsl.exe", "--exec", "test", "-e", converted],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        result["exists_wsl"] = cp.returncode == 0
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def command_exists(name: str) -> bool:
    if not has_wsl():
        return False
    cp = run_wsl(
        f'export PATH="$HOME/.local/bin:$PATH"; command -v {name}',
        check=False,
    )
    return cp.returncode == 0 and bool(cp.stdout.strip())


def decryptor_status() -> dict:
    if not has_wsl():
        return {"exists": False}
    cp = run_wsl(
        'test -x "$HOME/tp-link-decrypt/bin/tp-link-decrypt" '
        '&& echo "$HOME/tp-link-decrypt/bin/tp-link-decrypt"',
        check=False,
    )
    return {
        "exists": cp.returncode == 0,
        "path": cp.stdout.strip() or None,
    }


def env_report() -> dict:
    windows = {name: shutil.which(name) for name in ("git", "python", "aws")}
    names = (
        "git", "make", "gcc", "binwalk",
        "unsquashfs", "mksquashfs",
        "strings", "readelf", "objdump",
        "aws", "jefferson", "ubireader_extract_files",
    )
    return {
        "windows": windows,
        "wsl": {
            "available": has_wsl(),
            "tools": {name: command_exists(name) for name in names},
            "tp_link_decrypt": decryptor_status(),
        },
    }
