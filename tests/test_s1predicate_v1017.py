from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.s1predicate import _preceding_branches, _call_sites

row = {
    "direct_calls": [
        {
            "site": 0x1200,
            "target_symbol": "wlan_manager_onboarding_start",
            "objdump_symbol": "wlan_manager_onboarding_start",
        }
    ],
    "branches": [
        {"site": 0x1180, "mnemonic": "beqz", "operands": "v0,1208", "target": 0x1208},
        {"site": 0x11f0, "mnemonic": "bnez", "operands": "s0,1300", "target": 0x1300},
        {"site": 0x1000, "mnemonic": "beqz", "operands": "v1,1400", "target": 0x1400},
    ],
}

calls = _call_sites(row, "wlan_manager_onboarding_start")
assert len(calls) == 1
assert calls[0]["site"] == 0x1200

branches = _preceding_branches(row, 0x1200, span=0x90)
assert [b["site"] for b in branches] == [0x1180, 0x11f0]
assert branches[-1]["distance_to_call"] == 0x10

print("v1.0.17 predicate-slice regression test: OK")
