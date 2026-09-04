# V5PatchLab v1.0.1 — S3 + decryptor bootstrap fix

## What was wrong in v1.0

Two independent failures were seen on Windows + Ubuntu WSL.

### 1. `firmware-find` raised `ParseError`

v1.0 queried:

```text
https://download.tplinkcloud.com/?list-type=2&prefix=...
```

That hostname is suitable for serving objects, but in the observed environment
the bucket-list request returned an empty/non-XML response. Parsing it as S3
XML therefore produced:

```text
ParseError: no element found: line 1, column 0
```

v1.0.1 now prefers the canonical anonymous AWS S3 API:

```bash
aws s3api list-objects-v2 \
  --bucket download.tplinkcloud.com \
  --prefix firmware/Tapo_C200v5 \
  --no-sign-request
```

If AWS CLI is unavailable, it falls back to the AWS path-style S3 endpoint
rather than the CDN hostname.

### 2. `extract_keys.sh` stopped at `RSAKEY_1=`

The upstream script's binwalk extraction showed missing external extractors:

```text
jefferson
ubireader_extract_files
```

and then:

```text
RSAKEY_1=
```

The upstream script searches the extracted AX6000 tree for `nvrammanager`.
Without the filesystem extractors, that file may never be materialized.

The setup script now installs:

```text
jefferson
ubi_reader
awscli
```

and verifies both extractor commands before running the upstream script.

It also answers the upstream interactive prompt with `yes` explicitly.

## Repair existing installation

You do NOT need to reinstall the 700+ MB of packages manually.

From PowerShell:

```powershell
wsl -d Ubuntu
```

Then:

```bash
cd /mnt/c/Users/artbo/PycharmProjects/etude-tapoc200-v5
bash scripts/setup-v5patchlab-wsl.sh
```

The script is idempotent: already-installed apt packages are reused.

When it says `READY`, return to PowerShell:

```bash
exit
```

Then:

```powershell
python .\v5patchlab.py env-check
python .\v5patchlab.py decryptor-check
```

Expected WSL essentials:

```text
aws                     true
jefferson               true
ubireader_extract_files true
tp_link_decrypt.exists  true
```

Then retry:

```powershell
python .\v5patchlab.py firmware-find `
  --version 1.4.4 `
  --build 260527

python .\v5patchlab.py firmware-find `
  --version 1.4.6 `
  --build 260709
```

## Important interpretation

If the prefix returns objects but the exact build filter returns zero matches,
that does NOT prove the firmware never existed. It only means that exact object
is not present under the narrow public key prefix currently returned by the
bucket. Preserve the output so we can broaden the prefix/filename search in a
controlled way.

If `extract_keys.sh` still fails after `jefferson` and `ubi_reader` are present,
send:

```bash
cd ~/tp-link-decrypt
tail -n 120 tmp.fwextract/rsa_key_extractor.log
find tmp.fwextract -type f \( -name nvrammanager -o -name slpupgrade \) -print
```

Do not manually invent or substitute RSA keys.
