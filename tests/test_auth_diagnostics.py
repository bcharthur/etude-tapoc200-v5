from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from v5patchlab.boundtpap import (
    BoundAuthError,
    _safe_auth_response,
    auth_failure_diagnostic,
)


def main():
    raw = {
        "error_code": -40401,
        "result": {
            "data": {
                "code": -40404,
                "sec_left": 120,
                "time": 0,
                "max_time": 10,
                "nonce": "SECRET",
                "dev_confirm": "SECRET2",
                "stok": "SECRET3",
            }
        },
    }

    safe = _safe_auth_response(raw)
    blob = repr(safe)
    assert "SECRET" not in blob
    assert safe["error_code"] == -40401
    assert safe["result"]["data"]["sec_left"] == 120

    exc = BoundAuthError(
        "auth failed",
        stage="pake_share",
        response=raw,
    )
    diag = auth_failure_diagnostic(exc)
    assert diag["temporary_lockout_indicated"] is True
    assert diag["flattened_status"]["code"] == -40404
    assert diag["password_logged"] is False

    print("auth diagnostics self-test: OK")


if __name__ == "__main__":
    main()
