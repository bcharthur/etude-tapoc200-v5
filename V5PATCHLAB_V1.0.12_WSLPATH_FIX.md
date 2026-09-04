# V5PatchLab v1.0.12 — Windows/WSL path fix

Observed v1.0.11 failure:

```text
wslpath: C:UsersartboPycharmProjectsetude-tapoc200-v5firmware...
```

This is a wrapper bug, not a firmware/decryptor failure.

v1.0.12 invokes `wsl.exe --exec wslpath ...` so the Windows path is passed
without Linux-shell backslash escaping.

Diagnostic:

```powershell
python .\v5patchlab.py wsl-path-check `
  .\firmware\Tapo_C200v5_1.4.2_260513.bin
```

Expected:
- `exists_windows: true`
- `exists_wsl: true`
- WSL path beginning with `/mnt/c/Users/artbo/...`
- `error: null`

Then:

```powershell
python .\v5patchlab.py decrypt `
  .\firmware\Tapo_C200v5_1.4.2_260513.bin
```

No camera traffic is involved.
