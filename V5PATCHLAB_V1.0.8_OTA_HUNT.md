# V5PatchLab v1.0.8 — exact C200 V5 OTA hunt

The NORMAL bound TPAP/cloud experiment now returns `error_code=0` and confirms
`last_version=1.4.6 Build 260709 Rel.27675n`, but no URL/hash/size/filename.
Polling does not change. The camera-local cloud API is therefore no longer the
best acquisition route while the camera is already current.

Targets:

```text
1.4.4 Build 260527 Rel.28339n — 2026-06-02
1.4.6 Build 260709 Rel.27675n — 2026-07-17
```

Run both:

```powershell
python .\v5patchlab.py ota-hunt-both
```

The command searches:
- current FR/EN/US TP-Link C200 V5 support pages;
- Wayback snapshots around each release date;
- Wayback CDX URL metadata filtered by exact build/version/Rel tokens;
- known public firmware-index/research files;
- optional GitHub code search if `GITHUB_TOKEN` already exists locally.

It validates only URLs actually found by those public sources. It does not
generate timestamp/object-key permutations.

Evidence:

```text
evidence/runs/<UTC>-ota-hunt-<build>/
├── result.json
└── sources/
```

The high-value field is:

```text
interpretation.exact_ota_url_candidates
```

If an exact candidate is found:

```powershell
python .\v5patchlab.py firmware-download-url `
  --url "<EXACT URL>" `
  --out .\firmware\c200v5-1.4.6.bin

python .\v5patchlab.py decrypt .\firmware\c200v5-1.4.6.bin
python .\v5patchlab.py magic-scan .\firmware\c200v5-1.4.6.bin.dec
```

Then continue with `extract`, `find-main`, and `report`.
