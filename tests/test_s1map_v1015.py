from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.s1map import SEED_GROUPS, scan_rootfs

assert "factory_reset_state" in SEED_GROUPS
assert "provisioning_softap" in SEED_GROUPS
assert "wifi_events" in SEED_GROUPS

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    (td / "bin").mkdir()
    (td / "bin" / "sample").write_bytes(
        b"xxxxfactory_reset\x00softap\x00deauth\x00wpa_supplicant\x00"
    )
    rep = scan_rootfs(td)
    assert rep["file_hit_count"] == 1
    groups = rep["files_with_hits"][0]["hits"]
    joined = str(groups)
    assert "factory_reset_state" in joined
    assert "provisioning_softap" in joined
    assert "wifi_events" in joined
    assert "wifi_stack" in joined

print("v1.0.15 S1 static-map synthetic test: OK")
