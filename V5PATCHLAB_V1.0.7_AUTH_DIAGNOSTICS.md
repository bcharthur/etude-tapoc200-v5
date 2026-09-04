# V5PatchLab v1.0.7 — bound authentication diagnostics

## Result that motivated this revision

The scoped C200 V5 in NORMAL reports:

```text
pake:[2]
passcode_type=userpw
user_hash_type=0
username=MD5("admin")
cipher_suite=1
aes_128_ccm
iterations=5000
extra_crypt=null
```

Multiple `raw` candidate attempts reached `pake_share` but returned:

```text
error_code=-40401
```

This means `pake_register` itself is accepted and the failure occurs when the
camera validates the SPAKE2+ confirmation generated from the candidate
credential.

## Why stop blind attempts

Public Tapo authentication traces show some camera firmwares return failure
metadata such as:

```text
code
time
max_time
sec_left
```

and can enter a temporary authentication cooldown.

v1.0.6 discarded the full `pake_share` response and exposed only the outer
`error_code`.

v1.0.7 preserves ONLY safe status/counter fields from failed authentication
responses. It explicitly drops:

```text
dev_share
user_share
user_confirm
dev_confirm
salt
nonce
stok/session token
keys
password
derived credential
```

## Password-free command

```powershell
python .\v5patchlab.py bound-auth-status
```

This stops at `pake_register` and consumes no password attempt.

## One diagnostic authentication attempt

Only after you are comfortable there is no active cooldown:

```powershell
python .\v5patchlab.py bound-auth-probe `
  --candidate md5 `
  --password-label "Tapo account password"
```

One invocation means exactly one candidate.

If it fails, the output now contains:

```text
authentication.failure.stage
authentication.failure.server_status
authentication.failure.flattened_status
authentication.failure.temporary_lockout_indicated
```

If the server exposes `sec_left > 0`, `retry_after > 0`, `locked=true`, or the
known temporary-lock code shape, do not send another candidate until that
cooldown has expired.

## Candidate order

The public TPAP implementation used as a reference tries the following
candidate forms for `pake:[2]`:

```text
raw
md5(password)
SHA256(password).upper()
```

`raw` has already failed in this lab.

Therefore, after confirming there is no cooldown, the next bounded candidate is:

```text
md5
```

Only if that fails without a lockout indicator should `sha256` be tested.

There is no automatic candidate loop.

## Cloud-check gating

`bound-cloud-check` now aborts before sending any firmware API method when
bound authentication fails. The returned JSON explicitly says:

```text
cloud_check_sent=false
```

No firmware operation is sent on a failed authentication path.
