# C200 V5 — Third-party account v1.1 / TPAP pake:[0]

## Root cause of the v1.0 timeout

v1.0 used the old SSL-AES `encrypt_type=3` login.

The tested C200 V5 in SETUP advertises `pake:[0]`.
That means the setup-management branch is modern TPAP `default_userpw`.

v1.1 uses:

```text
discover
→ MAC-derived default_userpw
→ pake_register
→ SPAKE2+ P-256
→ pake_share
→ verify dev_confirm
→ derive AES-128-CCM key/base nonce
→ encrypted /stok=<session>/ds
```

No user/admin password is required for the handshake in SETUP.

## Install

```powershell
pip install -r .\requirements-thirdparty.txt
```

## Test handshake first

```powershell
python .\thirdparty.py probe
python .\thirdparty.py handshake
```

`handshake` does not change configuration.

Expected:

```text
session_established = true
cipher = aes_128_ccm
cipher_suite = 1
iterations = 5000
```

## Enable local RTSP/ONVIF account

Only after handshake succeeds:

```powershell
python .\thirdparty.py enable --username tapolab --arm
```

The password prompt uses `getpass`.

The encrypted TPAP session sends only:

```text
multipleRequest
├─ setAccountEnabled
│  └─ third_account = on
└─ changeThirdAccount
   └─ username/password for RTSP/ONVIF
```

The plaintext password and derived TPAP setup passcode are not printed or
written to disk.

After the change the tool checks TCP 443/554/2020/8800.
