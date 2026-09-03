# Research timeline and rationale

This file explains why each branch was explored and what was learned, so the project remains auditable rather than becoming a collection of ad-hoc tests.

## 1. Establish the exposed NORMAL surface

We first mapped the bound camera without assuming firmware internals. This identified HTTPS/TPAP, RTSP, ONVIF, Streamd, TDP and discovery behavior. The purpose was to separate services that are always present from features gated by third-party account state.

Result: several LAN surfaces exist, but none solves S1 because a radio-only attacker is not associated and therefore has no IP path while the camera is in NORMAL state.

## 2. Study SETUP/provisioning state

Factory reset exposed the open `Tapo_Cam_*` SoftAP and a TPAP `pake:[0]` profile. Public protocol research allowed reconstruction of the MAC-derived default passcode and establishment of a management session without a user account/password.

This branch was justified because any S1 attack that can force NORMAL -> SETUP would immediately gain a powerful follow-on path.

Confirmed SETUP consequences include:

- deterministic TPAP management bootstrap derived from public device identity/MAC;
- privileged configuration writes in SETUP;
- ability to create/enable a third-party camera account and open RTSP/ONVIF;
- unauthenticated Streamd video disclosure through the historical default-key path.

The missing question remained: **how can a nearby attacker force the camera into SETUP without touching it?**

## 3. Test known adjacent network bug families

ONVIF and other historical Tapo bug families were tested conservatively against V5 1.4.6. A transient service outage was investigated with baseline observation and shown to occur both before and after the test, so no causal ONVIF crash was claimed.

This branch was closed/low-priority because it did not reproduce on the current V5 firmware and still required LAN/IP reachability.

## 4. Acquire a vulnerable-side firmware

Exact 1.4.4/1.4.6 OTA object recovery was attempted through public indexes, support pages, bucket snapshots and Wayback. No exact current OTA URL was recovered. Rather than guess timestamp suffixes, a known public C200 V5 image was used:

`Tapo C200 V5 1.4.2 Build 260513 Rel.33069n`

Downloaded size: `7,388,116` bytes  
Encrypted SHA-256: `8d82e37250c3626b5fdcf5703b279a13195bee924110938e1423e729a3698a9e`

This was justified because it is exact same hardware and predates the 1.4.6 fixes, making it a useful vulnerable-side implementation reference even before the exact patched image is available.

## 5. Decrypt and extract the firmware

`tp-link-decrypt` recognized the Tapo wrapper, verified the firmware and produced a decrypted image.

Decrypted SHA-256: `7433bf6a0785caff7927fd78d9ada24660fea45d9257e3f777f0771acefe34b6`

Key structure observed after decryption:

- uImage at file offset `0x20400`;
- SquashFS little-endian at `0x380200`;
- gzip object near `0x6fdc44`.

Binwalk/unsquashfs extracted the root filesystem. Windows initially raised `WinError 1920` while traversing BusyBox/symlink reparse points; the tooling was fixed to skip those entries without treating the extraction as failed.

## 6. Identify the main application binary

The primary userspace binary was recovered at `squashfs-root/bin/main`.

Size: `3,856,820` bytes  
SHA-256: `3d5d7d8a35fdad2766848c6de2edd8fcb1db6f1392013d2d9556cb192cdfab37`

It contains the major networking/protocol families: TPAP/SPAKE2+, RTSP, ONVIF, Streamd, cloud and credential handling.

This justified a static-analysis branch: even though it is not the S1 trigger, understanding recovery/reset state machines and radio-adjacent code in the exact camera implementation can reveal which events might bridge RF-only input to provisioning/factory state.

## 7. Static findings relevant to known authentication/credential fixes

Two areas were mapped in detail:

### SPAKE2+ confirm path

`spake2p_MacVerify` is called from a wrapper that only transitions the SPAKE2+ context from state `4` to state `5` on a zero return. The primitive contains an unusual error-normalization path where a non-zero return from `spake2p_Mac` is converted to zero before returning. This is a **static anomaly**, not yet an exploitable bypass: the exact return semantics and reachable failure conditions must be verified before correlating it with CVE-2026-15315.

### Credential/private decrypt path

`tpssl_private_decrypt` uses RSA-1024/PKCS#1-style sizes including a `117`-byte maximum plaintext boundary. The disassembly suggests allocation/copy/NUL-termination logic that can produce a one-byte out-of-bounds write when the plaintext length reaches exactly 117 bytes. This is a strong static candidate but still needs exact call-path and reachability proof before being labeled CVE-2026-15316.

These findings are preserved because they help understand the codebase, but the project priority now returns to S1.

## 8. Current priority

The primary unresolved objective is:

**NORMAL/bound C200 V5 -> factory/provisioning state using nearby radio traffic only, with no association, no PSK, no IP path and no physical action.**

The next work therefore focuses on Wi-Fi management/action frames, driver/firmware handling and recovery/fallback state-machine behavior. TPAP/Streamd become the chain tail if and only if that radio-only pivot is achieved.
