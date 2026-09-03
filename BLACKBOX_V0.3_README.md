# Tapo C200 V5 — Black-box v0.3

This patch continues the no-credential LAN research.

It does NOT:
- use a password;
- compute a password guess;
- send `pake_share`;
- establish a TPAP session;
- brute force identities;
- fuzz memory;
- reboot/reset the camera.

## Key v0.2 interpretation

### RTSP TEARDOWN

`TEARDOWN /stream1` returned `200 OK` without authentication.

This is not yet a vulnerability. A TEARDOWN sent without a valid `Session`
may simply be accepted as an idempotent no-op.

Characterize it:

```powershell
python .\blackbox.py rtsp-teardown
```

If stream1, stream2, nonexistent URI, root URI, and bogus Session headers all
return 200, classify it as likely stateless/no-op unless impact can later be
demonstrated against a real session.

### 443 routing

`login/discover` returned the same successful body on:

```text
/
/app
/stream
```

This strongly suggests the JSON dispatcher is more important than the HTTP path.

## TPAP register step 1 only

```powershell
python .\blackbox.py tpap-register
```

The request is structurally based on the public community implementation of
TPAP/SPAKE2+:

```json
{
  "method": "login",
  "params": {
    "sub_method": "pake_register",
    "username": "<md5 identity>",
    "user_random": "<32 random bytes base64>",
    "cipher_suites": [1],
    "encryption": ["aes_128_ccm"],
    "passcode_type": "userpw",
    "stok": null
  }
}
```

Only SPAKE2+ step 1 is sent.

The tool compares exactly two identities:

```text
md5("admin")
md5("tapolab-blackbox-definitely-nonexistent")
```

This is not enumeration. The purpose is to see whether the device produces
different pre-auth register behavior for a conventional identity vs a fixed
nonexistent one.

Potential normal response fields include:

```text
dev_salt
dev_share
dev_random
iterations
extra_crypt
cipher_suites
encryption
```

A difference is only a candidate username-existence oracle, not an auth bypass.

## UDP/20002

```powershell
python .\blackbox.py tdp-20002
```

Sends one scoped unicast discovery query to:

```text
192.168.1.79:20002
```

No broadcast is emitted by this command.

## Full v0.3 run

```powershell
python .\blackbox.py sweep-v3
```

Evidence:

```text
evidence\runs\<timestamp>\
├── blackbox-v0.3.json
└── manifest.json
```
