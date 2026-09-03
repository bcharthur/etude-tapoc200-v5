from pathlib import Path
import shutil
import subprocess
import time


def capture_with_tshark(
    ip: str,
    output: Path,
    seconds: int = 60,
    interface: str | None = None,
) -> dict:
    exe = shutil.which("tshark")
    if not exe:
        return {
            "ok": False,
            "error": "tshark introuvable dans le PATH",
            "output": str(output),
        }

    cmd = [exe]
    if interface:
        cmd += ["-i", interface]
    cmd += [
        "-f", f"host {ip}",
        "-a", f"duration:{seconds}",
        "-w", str(output),
    ]

    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "elapsed_s": round(time.time() - started, 2),
        "command": cmd,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "output": str(output),
        "exists": output.exists(),
        "size": output.stat().st_size if output.exists() else 0,
    }
