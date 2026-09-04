from __future__ import annotations

import shlex
from pathlib import Path

from .evidence import sha256_file
from .wsl import run_wsl, wsl_path


def decrypt_firmware(
    firmware: str | Path,
    *,
    tool: str = "~/tp-link-decrypt/bin/tp-link-decrypt",
) -> dict:
    fw = Path(firmware).resolve()
    if not fw.exists():
        raise FileNotFoundError(fw)

    wfw = wsl_path(fw)

    probe = run_wsl(
        f"test -f {shlex.quote(wfw)} && printf '%s\\n' {shlex.quote(wfw)}",
        check=False,
    )
    if probe.returncode != 0:
        raise RuntimeError(
            "Windows -> WSL path conversion succeeded syntactically, but WSL "
            "cannot see the firmware file.\n"
            f"windows_path={fw}\n"
            f"wsl_path={wfw}\n"
            f"stderr={probe.stderr.strip()}"
        )

    cmd = f"{tool} {shlex.quote(wfw)}"
    cp = run_wsl(cmd)

    output = Path(str(fw) + ".dec")
    if not output.exists():
        raise RuntimeError(
            "tp-link-decrypt returned success but expected output "
            f"{output} was not found.\n"
            f"windows_input={fw}\n"
            f"wsl_input={wfw}\n"
            f"stdout:\n{cp.stdout}\n"
            f"stderr:\n{cp.stderr}"
        )

    return {
        "input": str(fw),
        "wsl_input": wfw,
        "input_sha256": sha256_file(fw),
        "output": str(output),
        "output_size": output.stat().st_size,
        "output_sha256": sha256_file(output),
        "tool": tool,
        "stdout": cp.stdout[-4000:],
        "stderr": cp.stderr[-4000:],
    }
