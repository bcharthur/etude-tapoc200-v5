from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.otaexact import (
    parse_index_text,
    target_match,
    object_url,
)


def main():
    fixture = """
2026-05-06 11:00:37 8050016 firmware/assigned/Tapo_C200v5_en_1.4.2_Build_260420_Rel.30119n_up_boot-signed_1778036432368.bin
2026-06-02 10:00:00 8050123 firmware/assigned/Tapo_C200v5_en_1.4.4_Build_260527_Rel.28339n_up_boot-signed_1779999999999.bin
https://download.tplinkcloud.com/firmware/assigned/Tapo_C200v5_en_1.4.6_Build_260709_Rel.27675n_up_boot-signed_1780000000000.bin
https://www.tp-link.com/us/support/download/tapo-h110/ 1.4.6
firmware/assigned/Tapo_C210v1_en_1.4.6_Build_260709_Rel.27675n_up_boot-signed_1780000000001.bin
"""
    rows = parse_index_text(fixture, source="fixture")
    assert len(rows) == 3

    old = [
        x for x in rows
        if target_match(
            x,
            version="1.4.4",
            build="260527",
            rel="28339n",
        )
    ]
    new = [
        x for x in rows
        if target_match(
            x,
            version="1.4.6",
            build="260709",
            rel="27675n",
        )
    ]
    assert len(old) == 1
    assert len(new) == 1
    assert "tapo-h110" not in " ".join(x["key"] for x in rows)
    assert "Tapo_C210" not in " ".join(x["key"] for x in rows)
    assert object_url(old[0]["key"]).startswith(
        "https://download.tplinkcloud.com/firmware/"
    )
    print("otaexact self-test: OK")


if __name__ == "__main__":
    main()
