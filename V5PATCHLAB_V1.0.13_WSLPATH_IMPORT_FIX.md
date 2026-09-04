# V5PatchLab v1.0.13 — `wsl-path-check` NameError fix

v1.0.12 added the `wsl-path-check` command, but its handler referenced
`wsl_path_diagnostic` without importing it into `cli.py`.

Observed error:

```text
[v5patchlab] ERROR: NameError: name 'wsl_path_diagnostic' is not defined
```

v1.0.13 imports the helper locally inside `cmd_wsl_path_check`, so the
command now resolves the symbol at execution time.

Recommended sequence:

```powershell
python .\v5patchlab.py wsl-path-check `
  .\firmware\Tapo_C200v5_1.4.2_260513.bin
```

If `exists_windows` and `exists_wsl` are both `true`:

```powershell
python .\v5patchlab.py decrypt `
  .\firmware\Tapo_C200v5_1.4.2_260513.bin
```

Do not run `magic-scan` on `.bin.dec` until the decrypt command has
actually created that file.
