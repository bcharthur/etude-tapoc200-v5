# Tapo C200 V5 — S1 Setup Deep Probe v0.7

Run only while manually connected to your own `Tapo_Cam_*` SSID.

## What the previous run confirmed

```text
Wi-Fi client        192.168.191.100/24
Camera/setup GW     192.168.191.1

443/tcp             OPEN
8800/tcp            OPEN
554/tcp             CLOSED/TIMEOUT
2020/tcp            CLOSED/TIMEOUT

HTTPS discover:
pake:[0]
tls:1
noc:0
port:443
```

The setup AP itself is Open / unencrypted.

## New command

```powershell
python .\s1lab.py setup-deep `
  --baseline-aes-sha256 16d988b90cfdd413d59ac2f0fd0667f7b94c25bed923c110417e91000a809e24
```

It performs only bounded, read-only/pre-auth probes:

1. TCP 80/443/554/2020/8800.
2. Existing HTTPS `login/discover`.
3. Phase-1 legacy camera login challenge:

```json
{
  "method": "login",
  "params": {
    "cnonce": "<random>",
    "encrypt_type": "3",
    "username": "admin"
  }
}
```

It does NOT send:
- password;
- digest_passwd;
- second login;
- securePassthrough;
- any setup/configuration command.

4. Unauthenticated Streamd/8800 challenge.
5. TDP v2 discovery/decryption using our own ephemeral RSA key.
6. Compare setup-state TDP AES-material SHA-256 against the pre-reset baseline.

## Important interpretation

Public community research on Tapo cloudless onboarding uses the same setup
address `192.168.191.1` and this encrypt-type-3 two-phase login family.

A phase-1 response containing `nonce` and `device_confirm` only proves that the
challenge is reachable. It does not prove authentication bypass.

The next step, if phase 1 matches, should be decided from the empirical response
before sending phase 2.
