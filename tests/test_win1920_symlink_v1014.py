from pathlib import Path
import os
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.extract import _safe_tree_inventory, find_main_report

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    bindir = td / "squashfs-root" / "bin"
    bindir.mkdir(parents=True)

    main = bindir / "main"
    main.write_bytes(
        b"\x7fELF" + b"\x00" * 65536
        + b"device_confirm\x00pake_share\x00ciphertext\x00ONVIF\x00"
    )

    # Model the firmware's BusyBox-style symlink entry.
    link = bindir / "dmesg"
    try:
        os.symlink("busybox", link)
    except (OSError, NotImplementedError):
        # The test still verifies the regular-file path on platforms where
        # creating a symlink needs privileges.
        pass

    inv = _safe_tree_inventory(td)
    assert any(Path(x["path"]).name == "main" for x in inv["files"])

    rep = find_main_report(td)
    assert rep["candidate_count"] >= 1
    assert rep["candidates"][0]["path"].endswith("main")
    assert "device_confirm" in rep["candidates"][0]["anchors"]

print("v1.0.14 WinError1920/symlink regression test: OK")
