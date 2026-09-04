from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.s3 import _normalize_aws_rows

def main():
    rows = _normalize_aws_rows({
        "Contents": [
            {
                "Key": "firmware/Tapo_C200v5_en_1.4.6_Build_260709_Rel.test.bin",
                "Size": 123,
                "ETag": '"abc"',
                "LastModified": "2026-07-09T00:00:00Z",
            }
        ]
    })
    assert rows[0]["size"] == 123
    assert rows[0]["etag"] == "abc"
    assert rows[0]["source"] == "aws-s3api"
    print("s3 logic self-test: OK")

if __name__ == "__main__":
    main()
