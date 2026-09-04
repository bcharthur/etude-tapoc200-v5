from pathlib import Path
import contextlib
import io
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import v5patchlab.wsl as wslmod
from v5patchlab.cli import build_parser

original = wslmod.wsl_path_diagnostic
try:
    wslmod.wsl_path_diagnostic = lambda p: {
        "input": str(p),
        "exists_windows": True,
        "exists_wsl": True,
        "wsl_path": "/mnt/c/test.bin",
        "error": None,
    }

    parser = build_parser()
    args = parser.parse_args(["wsl-path-check", r".\firmware\test.bin"])

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = args.func(args)

    assert rc == 0
    data = json.loads(buf.getvalue())
    assert data["exists_windows"] is True
    assert data["exists_wsl"] is True
    assert data["error"] is None
finally:
    wslmod.wsl_path_diagnostic = original

print("v1.0.13 wsl-path-check CLI regression test: OK")
