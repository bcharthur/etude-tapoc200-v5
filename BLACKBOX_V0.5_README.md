# Tapo C200 V5 — Black-box v0.5

## What v0.4 confirmed

Without credentials, the C200 V5 responds on UDP/20002 to modern TDP v2
discovery containing an ephemeral RSA public key.

Empirically observed outer metadata includes:

```text
device_type       SMART.IPCAMERA
device_model      C200
hardware_version  5.0
firmware_version  1.4.6 Build 260709 Rel.27675n
factory_default   false
TPAP              pake:[2], tls:1, noc:1, port:443
HTTPS support     true
encrypt_info      AES
```

Port 20004 did not respond.

## Why encrypt_info can be decrypted

The device encrypts a discovery AES key/IV to the RSA public key supplied by
the requester. The corresponding ephemeral RSA private key therefore allows
the requester to decrypt its own response.

The algorithm implemented by python-kasa is:

```text
base64(encrypt_info.key)
  -> RSA OAEP SHA-1 / MGF1 SHA-1
  -> first 16 bytes = AES key
  -> next 16 bytes  = IV

base64(encrypt_info.data)
  -> AES-128-CBC
  -> PKCS#7 unpadding
  -> JSON
```

v0.5 implements only that discovery decryption.

## Commands

### Redacted discovery decryption

```powershell
python .\blackbox.py tdp-decrypt
```

By default potentially personal LAN values are redacted:

```text
connect_ssid
owner
device_id
```

The AES key and IV are never printed.

### Show the local values

Only if you explicitly want to inspect your own camera's response:

```powershell
python .\blackbox.py tdp-decrypt --show-values
```

Do not share that output without reviewing/redacting it first.

### Stability profile

```powershell
python .\blackbox.py tdp-decrypt-profile --count 4
```

This performs four fresh RSA-key discovery exchanges and persists only SHA-256
fingerprints for:

```text
AES key+IV
AES ciphertext
decrypted plaintext
```

This answers:

```text
Does the device reuse the same discovery AES material?
Is the encrypted data stable?
Is the decrypted discovery blob stable?
```

No AES key or IV is persisted.

### Evidence-safe run

```powershell
python .\blackbox.py sweep-v5
```

Produces:

```text
evidence\runs\<timestamp>\
├── blackbox-v0.5.json
└── manifest.json
```

The manifest states:

```text
credentials_used = false
password_used = false
pake_share_sent = false
destructive_tests = false
decrypted_sensitive_values_persisted = false
```
