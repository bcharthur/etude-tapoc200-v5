from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.camera_fw import _urls
from v5patchlab.releases import PAT

def main():
    x = {
        "result": {
            "fwUrl": "http://download.tplinkcloud.com/firmware/test.bin"
        }
    }
    u = _urls(x)
    assert u and u[0]["url"].endswith("test.bin")
    m = PAT.search("Tapo C200(EU)_V5_1.4.6 Build 260709")
    assert m and m.group(1) == "1.4.6" and m.group(2) == "260709"
    print("camera/release helper self-test: OK")

if __name__ == "__main__":
    main()
