from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.s1controlflow import parse_objdump, _first_target, _materialized_addresses
from v5patchlab.s1observe import parse_netsh_networks

sample = r'''
004d0708 <example>:
  4d0708:       3c040070        lui     a0,0x70
  4d070c:       24841234        addiu   a0,a0,4660
  4d0710:       0411fa52        bal     4cf06c <spake2p_MacVerify>
  4d0714:       00000000        nop
  4d0718:       14400004        bnez    v0,4d072c <example+0x24>
  4d071c:       00000000        nop
'''
ins = parse_objdump(sample)
assert len(ins) == 6, ins
assert ins[2].mnemonic == "bal"
assert _first_target(ins[2].operands) == 0x4CF06C
mats = _materialized_addresses(ins)
assert mats and mats[0]["address"] == 0x00701234, mats

netsh = r'''
SSID 1 : Home
    Network type            : Infrastructure
    BSSID 1                 : aa:bb:cc:dd:ee:ff
SSID 2 : Tapo_Cam_3ADA
    Network type            : Infrastructure
    BSSID 1                 : de:62:79:8b:3a:da
'''
rows = parse_netsh_networks(netsh)
assert len(rows) == 2
assert rows[1]["ssid"] == "Tapo_Cam_3ADA"
assert rows[1]["bssids"] == ["de:62:79:8b:3a:da"]

print("v1.0.16 S1 control-flow/observer synthetic test: OK")
