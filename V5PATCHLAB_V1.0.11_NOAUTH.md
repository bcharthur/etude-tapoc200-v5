# V5PatchLab v1.0.11 — no-account path

This version makes Tapo-account authentication optional and non-preferred.

## Why

The previous `cloud-account-fw` branch hit a TLS-chain error on the user's
Windows host and, more importantly, the user does not want to authenticate to
the Tapo account.

That is fine: account authentication is not required for the next useful work.

## Path A — camera currently in SETUP

Use the already-proven TPAP `pake:[0]` bootstrap path:

```powershell
python .\v5patchlab.py camera-fw
```

No Tapo account, Camera Account password, or user password is requested.

v1.0.11 now also reads:

```text
getCloudConfig(upgrade_info)
```

in addition to device info and upgrade status.

If the SETUP camera somehow has upstream Internet connectivity, an optional
refresh is:

```powershell
python .\v5patchlab.py camera-fw --refresh
```

This sends `checkFirmwareVersionByCloud`, then reads the metadata. It still
does not authenticate to a Tapo account and does not start a firmware update.

A factory-reset camera on its own SoftAP normally has no upstream Internet, so
`--refresh` may legitimately fail or return no new data.

## Path B — start static analysis now with a public V5 image

The 2026 public bucket snapshot contains an exact C200 V5 image:

```text
Tapo C200 V5
1.4.2 Build 260513 Rel.33069n
```

Show it:

```powershell
python .\v5patchlab.py public-base-info
```

Download it:

```powershell
python .\v5patchlab.py public-base-fetch
```

If the TP-Link CDN shows the same local certificate-chain problem:

```powershell
python .\v5patchlab.py public-base-fetch --insecure
```

`--insecure` applies only to that public firmware-file download.

Why 1.4.2 is useful:

- it is the same hardware family: C200 V5;
- it predates 1.4.6;
- CVE-2026-15315 and CVE-2026-15316 are fixed by 1.4.6;
- therefore 1.4.2 is a useful vulnerable-side image for locating the old
  `device_confirm` / encrypted-credential handling even without exact 1.4.4.

The diff will be noisier than 1.4.4 -> 1.4.6, but static analysis can begin now.

## Path C — exact fixed side without account auth

The exact current 1.4.6 is already running on the physical camera.

The clean exact acquisition path is therefore:

```text
UART / U-Boot -> 8 MiB NOR dump -> carve firmware/rootfs -> /bin/main
```

This produces the exact fixed binary from the user's own device and avoids all
cloud-account authentication.

The useful pair then becomes:

```text
public 1.4.2 vulnerable side
vs
camera-dumped 1.4.6 fixed side
```

For CVE-2026-15315 / 15316 this is sufficient to identify the changed code
families; exact 1.4.4 can remain a later acquisition target.

## What not to do now

Do not keep retrying:

```text
cloud-account-fw
ota-exact-both --wayback-insecure
```

unless a genuinely new public index appears.

The account TLS error is not evidence that the credentials were wrong. The TLS
handshake failed before the service could evaluate them.
