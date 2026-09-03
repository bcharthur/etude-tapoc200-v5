# C200 V5 1.4.2 static-analysis findings

## Evidence identity

Firmware: `1.4.2 Build 260513 Rel.33069n`  
Encrypted SHA-256: `8d82e37250c3626b5fdcf5703b279a13195bee924110938e1423e729a3698a9e`  
Decrypted SHA-256: `7433bf6a0785caff7927fd78d9ada24660fea45d9257e3f777f0771acefe34b6`

`main` SHA-256: `3d5d7d8a35fdad2766848c6de2edd8fcb1db6f1392013d2d9556cb192cdfab37`

## ELF layout

- `.text` VMA `0x00412140`, file offset `0x00012140`
- `.rodata` VMA `0x006c4150`, file offset `0x002c4150`
- `.plt` VMA `0x00760c80`
- `.data` VMA `0x00774dd0`
- `.got` VMA `0x007bbd70`
- `.bss` VMA `0x007bd320`

For `.rodata`, observed string addresses follow `VMA = file_offset + 0x400000`.

## SPAKE2+ symbols

Examples recovered from the dynamic symbol table:

- `0x004ceea4` `HMAC_sha_HMAC_SHA256`
- `0x004cef98` `spake2p_Mac`
- `0x004cf06c` `spake2p_MacVerify`
- `0x004cf230` `spake2p_KDF`
- `0x004cf324` `__Spake2p_Init`
- `0x004cfa28` `spake2p_GenerateKeys`

### Confirm wrapper state transition

The wrapper around `0x004d0640` requires context state `4`, selects role-dependent material, serializes a point, invokes `spake2p_MacVerify`, and writes state `5` only when the return is zero.

This establishes a concrete authentication state transition:

`state 4 -> peer confirm verification -> state 5`

### `spake2p_MacVerify` anomaly

The disassembly contains:

```text
call spake2p_Mac
if return == 0: compare 32-byte MAC constant-time
if return != 0: return 0
```

This means a non-zero result from `spake2p_Mac` is normalized to zero by `spake2p_MacVerify`. That behavior is unusual and warrants comparison with 1.4.6. It is **not yet proof of a remotely triggerable authentication bypass** because the meaning/reachability of each `spake2p_Mac` non-zero return still needs to be established.

## Base64 wrappers

- `0x004d3098` `tpssl_Base64_Decode`, size 92 bytes
- `0x004d194c` `tpssl_base64_decode`, size 108 bytes

`tpssl_Base64_Decode` performs size arithmetic and delegates through a GOT-resolved helper. The helper identity and exact argument contract should be resolved before drawing overflow conclusions from this wrapper alone.

## RSA/private decrypt symbols

- `0x004d4ae0` `tpssl_rsa_decrypt`, size 588 bytes
- `0x004d5a34` `tpssl_private_decrypt`, size 752 bytes
- imported `mbedtls_rsa_pkcs1_decrypt`
- imported `mbedtls_pk_decrypt`
- imported `mbedtls_pk_parse_key`

The private-decrypt path uses the RSA-1024 PKCS#1 plaintext maximum of 117 bytes. The observed allocation/copy/NUL-termination pattern is consistent with a possible `buffer[117] = 0` write after allocating exactly 117 bytes when the output length is maximal. Preserve as a **strong static candidate**, not yet a confirmed CVE mapping.

## PEM strings

The strings `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----` are adjacent parser/format constants; no embedded Base64 key body exists between them. The binary references runtime/device certificate paths including `/tmp/data/device_certificate/private_key.pem`, consistent with device-specific material rather than a universal key embedded at that location.

## Relation to S1

These auth/credential findings matter for S2/S3 and for understanding the codebase, but do not directly provide the required S1 trigger. A radio-only attacker in NORMAL state cannot invoke TPAP/HTTPS/RTSP/ONVIF without first gaining an IP path or forcing a state transition.
