# C200 V5 — S1 Setup v0.8

Run only while connected to the scoped camera's own setup SSID.

The scope gate requires the SSID to match the last four hex digits in
`config/scope.json`.

## Why v0.8 exists

In NORMAL state:

```text
TCP/8800 -> 401 Digest
```

After factory reset / SETUP:

```text
TCP/8800 -> 200 OK
Key-Exchange:
  cipher="AES_128_CBC"
  username="none"
  padding="PKCS7_16"
  algorithm="MD5"
  encrypt_type="3"
  nonce="..."
X-Session-Id: ...
```

This does not yet prove media disclosure.

Public Tapo clients such as go2rtc treat `username="none"` using the historical
Tapo setup/default secret associated with CVE-2022-37255. The official CVE
record names C310 1.3.0, NOT this C200 V5, so v0.8 treats this only as a
regression hypothesis.

## 1. Bounded stream smoke test

```powershell
python .\s1lab.py setup-stream-smoke
```

The test:
1. requires scoped `Tapo_Cam_XXXX`;
2. connects only to the DHCP gateway on TCP/8800;
3. sends no Authorization header;
4. requires Streamd to answer `username="none"`;
5. derives the historical AES key/IV;
6. sends one normal preview request;
7. reads at most 256 KiB / ~3 seconds;
8. does NOT save media;
9. reports only whether a video/mp2t part is present and whether decrypted bytes
   have MPEG-TS sync spacing.

Strong positive:

```text
media_observed = true
decryptable_mpeg_ts_observed = true
```

That would demonstrate a live-media path in SETUP without user credentials.

It would NOT automatically mean CVE-2022-37255 applies, because that CVE
specifically documents C310 1.3.0 RTSP/default credentials.

## 2. Confirm TPAP pake:[0] register branch

```powershell
python .\s1lab.py setup-tpap0-register
```

This sends only:

```text
pake_register
passcode_type = default_userpw
```

No passcode is computed or sent, no `pake_share`, no session.

A successful response with:

```text
dev_salt
dev_random
dev_share
```

would confirm that SETUP is using the modern TPAP default-user-password branch,
not the legacy SSL-AES login shape tested in v0.7.
