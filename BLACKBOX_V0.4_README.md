# Tapo C200 V5 — Black-box v0.4

## Correction de classification

The v0.3 result:

```text
MD5("admin") -> pake_register success
unknown hash -> -40209
```

must NOT currently be reported as Camera Account username enumeration.

For TPAP discovery `pake:[2]`, `admin` is used by public community
implementations as the protocol identity. On this camera, the configured
RTSP/ONVIF Camera Account was `tapolab`, yet the TPAP register still accepts
`MD5("admin")`, which is consistent with that protocol-level identity.

## Install one Python dependency

```powershell
python -m pip install -r .\blackbox-v0.4-requirements.txt
```

Only `cryptography` is added, for generating an ephemeral RSA public key used
by modern TDP discovery.

No private key is saved.

---

## 1. Profile TPAP pake_register randomness

```powershell
python .\blackbox.py tpap-profile --count 6
```

Measures:

```text
dev_salt stable?
dev_random unique?
dev_share unique?
iterations stable?
cipher suite stable?
encryption stable?
```

No password and no `pake_share`.

Expected PAKE-like behavior:

```text
dev_salt      may be stable
dev_random    changes
dev_share     changes
iterations    stable
```

## 2. TPAP HTTP path matrix

```powershell
python .\blackbox.py tpap-paths
```

Same valid `pake_register` request on:

```text
/
/app
/stream
/does-not-exist
```

If all succeed, it supports the hypothesis of a catch-all JSON dispatcher.
That is architectural behavior, not an auth bypass.

## 3. Modern TDP v2 RSA-key probe

```powershell
python .\blackbox.py tdp-v2
```

The v0.3 16-byte probe was insufficient for current TDP implementations.

v0.4 builds the modern TDP v2 probe:

```text
version = 2
op_code = probe
flags   = 17
payload = {"params":{"rsa_key":"-----BEGIN PUBLIC KEY-----..."}}
CRC32   = recomputed
```

It sends ONE unicast request to each:

```text
192.168.1.79:20002
192.168.1.79:20004
```

No broadcast.

The response's outer JSON is parsed. `encrypt_info` is not decrypted in v0.4.

## 4. Full run

```powershell
python .\blackbox.py sweep-v4
```

Evidence:

```text
evidence\runs\<timestamp>\
├── blackbox-v0.4.json
└── manifest.json
```

Explicit properties:

```text
credentials_used = false
password_used     = false
pake_share_sent   = false
destructive_tests = false
```
