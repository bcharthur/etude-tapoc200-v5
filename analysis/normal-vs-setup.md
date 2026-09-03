# C200 V5 — NORMAL vs SETUP state map

- NORMAL source: `evidence\runs\20260903T141439Z-state\state-NORMAL.json`
- SETUP source: `evidence\runs\20260903T135252Z-state\state-SETUP.json`

| Surface | NORMAL | SETUP |
|---|---|---|
| TCP/80 | False | False |
| TCP/443 | True | True |
| TCP/554 | False | False |
| TCP/2020 | False | False |
| TCP/8800 | True | True |
| TPAP pake | `[2]` | `[0]` |
| TPAP noc | `1` | `0` |
| Streamd initial status | `HTTP/1.0 401 Unauthorized` | `HTTP/1.0 200 OK` |
| Streamd Key-Exchange | `None` | `['cipher="AES_128_CBC" username="none" padding="PKCS7_16" algorithm="MD5" encrypt_type="3" nonce="4e1542676265cd5c14f8c119268a00cd"']` |

## TDP state

- NORMAL AES-material SHA-256: `dc56b4429ad192ea042aec0d1d0e0500509b5cabe0b10118777c85c0824b4a4d`
- SETUP AES-material SHA-256: `dc56b4429ad192ea042aec0d1d0e0500509b5cabe0b10118777c85c0824b4a4d`
- Same material: `True`

## Interpretation

Use this as a state oracle and correlate it with:

- UART reset/reboot logs;
- SPI NOR changed offsets/pages;
- Ghidra xrefs to config/reset/provisioning writers.
