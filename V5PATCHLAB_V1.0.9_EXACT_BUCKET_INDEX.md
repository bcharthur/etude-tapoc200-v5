# V5PatchLab v1.0.9 — strict C200 V5 bucket/index hunt

## Why v1.0.8 was inconclusive

The previous run did **not** prove that the target objects are absent.

Three concrete problems were visible:

1. Every Wayback/CDX request failed locally with:

```text
SSL: CERTIFICATE_VERIFY_FAILED
Basic Constraints of CA cert not marked critical
```

So archive coverage was zero.

2. Candidate scoring accepted a generic version token (`1.4.4` / `1.4.6`)
near an unrelated H110 URL. That H110 result was noise.

3. Current TP-Link support pages contain many country/navigation links, so the
result became huge without adding object-key evidence.

## New public source

A 2026 public repository exists:

```text
Ripthulhu/tp-link-tapo-firmware
```

It is a snapshot of TP-Link's public firmware bucket and contains C200 V5 keys
such as:

```text
firmware/assigned/
Tapo_C200v5_en_1.4.2_Build_260513_Rel.33069n_
up_boot-signed_<epoch>.bin
```

This confirms the exact C200 V5 object-key grammar.

The repository was created/pushed on 2026-06-23, so it cannot be expected to
contain the July 1.4.6 release. Its absence is therefore not meaningful for
1.4.6. The 1.4.4 target is older and remains worth checking in all three index
files.

## What v1.0.9 changes

`ota-exact` only recognizes objects that parse as:

```text
Tapo_C200v5
+ exact semantic version
+ exact Build
+ exact Rel
```

A bare `1.4.6` elsewhere can no longer create a candidate.

It scans:

```text
Ripthulhu all_firmware.txt
Ripthulhu tapo_firmware.txt
Ripthulhu tapo_firmware_urls.txt
```

It also makes bounded public S3-style prefix-list requests:

```text
firmware/assigned/
Tapo_C200v5_en_1.4.4_Build_260527_Rel.28339n
```

and similarly for 1.4.6.

No timestamp suffix is guessed.

## Windows / Wayback TLS fix

`certifi` is now in `requirements-v5patchlab.txt`.

Install/update dependencies:

```powershell
python -m pip install -r .\requirements-v5patchlab.txt
```

The exact hunter uses the certifi CA bundle automatically when available.

If your network still presents the same invalid Wayback certificate chain,
you can give a known CA bundle:

```powershell
python .\v5patchlab.py ota-exact-both `
  --ca-bundle "C:\path\to\ca-bundle.pem"
```

For this one public, non-secret archive metadata request only, an explicit
last-resort option exists:

```powershell
python .\v5patchlab.py ota-exact-both `
  --wayback-insecure
```

That switch applies only to `web.archive.org` CDX metadata. TP-Link/GitHub
downloads remain certificate-verified.

## Recommended run

First:

```powershell
python -m pip install -r .\requirements-v5patchlab.txt
python .\v5patchlab.py ota-exact-both
```

If and only if Wayback still reports the same CA-chain error:

```powershell
python .\v5patchlab.py ota-exact-both `
  --wayback-insecure
```

## What to send back

The output is intentionally compact. The high-value sections are:

```text
public_indexes.*.exact_matches
live_bucket.attempts
wayback_cdx_exact
exact_matches
validations
interpretation
```

Evidence directories:

```text
evidence/runs/<UTC>-ota-exact-260527/
evidence/runs/<UTC>-ota-exact-260709/
```

## Interpretation rule

```text
exact_matches != []
    -> download / decrypt / extract / binary diff

exact_matches == []
and Wayback failed
    -> acquisition still incomplete

exact_matches == []
and all exact sources completed
    -> switch to cloud fwId / newer bucket snapshot / hardware dump
       rather than guessing timestamp suffixes
```
