# V5PatchLab v1.0.6 — bound TPAP `pake:[2]`

## Why PyTapo failed

The NORMAL probe proves the same physical camera is now:

```text
192.168.1.79
pake:[2]
noc:1
443/554/2020/8800 reachable
```

The `tapolab` credential created in the SETUP experiment is the
`third_account` used for RTSP/ONVIF compatibility.

A failure of:

```text
Tapo(host, "tapolab", password)
→ Invalid authentication data
```

does not prove that NORMAL TPAP management authentication is unavailable.
It primarily shows that this `third_account` credential did not satisfy the
management authentication method used by PyTapo on this firmware.

Current public TPAP implementations classify:

```text
pake:[0] → default_userpw
pake:[2] → userpw
```

and use the management identity `admin` on the wire for this TPAP family.

v1.0.6 therefore tests the V5's own advertised bound TPAP mode directly.

## Step 1 — inspect register profile with NO PASSWORD

Run:

```powershell
python .\v5patchlab.py bound-register
```

This sends only:

```text
login / pake_register
passcode_type = userpw
username = hash(admin)
cipher suite = 1
aes_128_ccm
```

It does NOT send `pake_share`.

Important output:

```text
extra_crypt.type
extra_crypt.params
iterations
dev_share_len
user_hash_type
```

This tells us exactly how this V5 wants the supplied user password transformed.

## Step 2 — one authentication attempt

One invocation tests one candidate only.

Start with:

```powershell
python .\v5patchlab.py bound-auth-probe `
  --candidate raw `
  --password-label "Camera Account password"
```

The password is entered with `getpass`.

The command does not log:

```text
password
candidate value
derived credential
```

If authentication succeeds, it sends only:

```text
getDeviceInfo/basic_info
```

### What password should be entered?

`tapolab`/Camera Account and the TP-Link/Tapo account password are conceptually
different credentials.

The Camera Account password is reasonable to try first because it stays local,
but the preceding PyTapo result suggests it may not be the bound management
credential on this firmware.

PyTapo's documented fallback for some camera/firmware combinations is:

```text
user = admin
password = TP-Link cloud account password
```

If you explicitly choose to test that fallback, enter the cloud password only
at the local `getpass` prompt. Never paste it into chat or put it on the command
line.

## Candidate forms

The default is:

```text
raw
```

If and only if that fails, explicit alternatives are:

```powershell
--candidate md5
--candidate sha256
```

There is no automatic three-attempt loop. This minimizes unnecessary failed
authentication attempts.

After selecting the explicit candidate, v1.0.6 also applies the
`extra_crypt` scheme advertised by `pake_register`, including:

```text
password_shadow:
  passwd_id 1 → MD5-crypt
  passwd_id 2 → SHA1
  passwd_id 3 → SHA1(MD5(password) + "_" + MAC)
  passwd_id 5 → SHA256-crypt

password_authkey

password_sha_with_salt
```

## Step 3 — cloud check after a proven TPAP auth

Once `bound-auth-probe` succeeds with a known candidate:

```powershell
python .\v5patchlab.py bound-cloud-check `
  --candidate raw `
  --password-label "same password as successful probe" `
  --poll-seconds 20 `
  --interval 2
```

It performs:

```text
getDeviceInfo
getCloudConfig(upgrade_info)
getFirmwareUpdateStatus

checkFirmwareVersionByCloud

poll:
  getCloudConfig(upgrade_info)
  getFirmwareUpdateStatus
```

No firmware installation action is included.

## Best outcome

```text
bound TPAP auth OK
cloud check error_code 0
upgrade_info populated
download.tplinkcloud.com URL recovered
```

Then the exact current package can be downloaded to the PC and passed to:

```text
tp-link-decrypt
→ binwalk
→ find-main
→ V5 patch diff
```
