# v1.1.1 — SEC1 point encoding fix

## Root cause

The C200 V5 `pake_register` response returns `dev_share` as an uncompressed
SEC1 P-256 point:

```text
length = 65 bytes
prefix = 0x04
layout = 04 || X(32) || Y(32)
```

v1.1 incorrectly accepted only compressed points:

```text
length = 33 bytes
prefix = 0x02 or 0x03
```

The SPAKE2+ fixed M/N constants remain compressed, so the decoder now accepts
both legal SEC1 forms.

No handshake parameters, passcode derivation, PBKDF2 settings, transcript
construction or AES-CCM derivation were changed.

## Run

```powershell
python .\thirdparty.py probe
python .\thirdparty.py handshake
```

If the handshake succeeds, only then run:

```powershell
python .\thirdparty.py enable --username tapolab --arm
```
