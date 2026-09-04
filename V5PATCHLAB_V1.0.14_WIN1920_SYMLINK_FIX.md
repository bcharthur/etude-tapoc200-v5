# V5PatchLab v1.0.14 — Windows WinError 1920 / SquashFS symlink fix

Observed on a WSL/binwalk extraction written under `C:\...`:

```text
OSError: [WinError 1920] ...\squashfs-root\bin\dmesg
```

This is a Windows-side traversal problem, not evidence that binwalk or
unsquashfs failed. Embedded root filesystems commonly contain BusyBox
symlinks such as `/bin/dmesg`. WSL can create those links on `/mnt/c`, while
Windows Python may expose them as inaccessible reparse points.

v1.0.14 changes both post-extraction inventory and `find-main` to:
- use `os.walk(..., followlinks=False)`;
- skip symlinks/reparse points and individual OSError entries;
- continue scanning regular files;
- report skipped entries instead of aborting the command.

The existing `analysis\c200v5-142` extraction can be reused. You do not
need to delete or recreate it just because v1.0.13 aborted while listing
`bin\dmesg`.

Recommended next command after installing this patch:

```powershell
python .\v5patchlab.py find-main `
  .\analysis\c200v5-142
```

If you want a fresh extraction report afterwards:

```powershell
python .\v5patchlab.py extract `
  .\firmware\Tapo_C200v5_1.4.2_260513.bin.dec `
  --out .\analysis\c200v5-142
```
