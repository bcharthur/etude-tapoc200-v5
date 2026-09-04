from __future__ import annotations
import json
import shlex
import urllib.parse
import urllib.request
import ssl
import xml.etree.ElementTree as ET
from pathlib import Path
import certifi
from .wsl import command_exists, run_wsl

BUCKET = "download.tplinkcloud.com"
PREFIX = "firmware/Tapo_C200v5"


def _normalize_aws_rows(obj):
    rows = []
    for x in (obj or {}).get("Contents", []) or []:
        key = x.get("Key")
        if not key:
            continue
        rows.append({
            "key": key,
            "size": int(x.get("Size") or 0),
            "last_modified": x.get("LastModified"),
            "etag": str(x.get("ETag") or "").strip('"'),
            "source": "aws-s3api",
        })
    return rows


def _list_via_wsl_aws(prefix):
    if not command_exists("aws"):
        raise RuntimeError("WSL aws CLI not installed")
    cp = run_wsl(
        "aws s3api list-objects-v2 "
        f"--bucket {shlex.quote(BUCKET)} "
        f"--prefix {shlex.quote(prefix)} "
        "--no-sign-request --output json"
    )
    obj = json.loads(cp.stdout)
    return _normalize_aws_rows(obj)


def list_objects(prefix=PREFIX):
    errors = []
    try:
        return _list_via_wsl_aws(prefix), {"backend": "wsl-aws"}
    except Exception as exc:
        errors.append(f"aws: {type(exc).__name__}: {exc}")

    params = urllib.parse.urlencode({
        "list-type": "2",
        "prefix": prefix,
        "max-keys": "1000",
    })
    url = f"https://s3.amazonaws.com/{BUCKET}/?{params}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "V5PatchLab/1.0.2"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
        if not raw.strip():
            raise RuntimeError("empty S3 listing response")
        root = ET.fromstring(raw)
        rows = []
        for c in root.findall(".//{*}Contents"):
            key = c.findtext("{*}Key") or c.findtext("Key")
            if key:
                rows.append({
                    "key": key,
                    "size": int(
                        c.findtext("{*}Size")
                        or c.findtext("Size")
                        or 0
                    ),
                })
        return rows, {"backend": "path-style-s3"}
    except Exception as exc:
        errors.append(f"path-style: {type(exc).__name__}: {exc}")

    return [], {
        "backend": None,
        "listing_available": False,
        "errors": errors,
        "note": (
            "Bucket listing is unavailable from this environment. "
            "Direct object downloads may still work when an exact URL/key is known."
        ),
    }


def find(build=None, version=None, region=None):
    rows, meta = list_objects()
    matches = []
    for r in rows:
        s = r["key"].lower()
        if build and build.lower() not in s:
            continue
        if version and version.lower() not in s:
            continue
        if region and f"_{region.lower()}_" not in s:
            continue
        matches.append(r)
    return {
        "backend": meta,
        "total_objects_under_prefix": len(rows),
        "matches": matches,
    }



def _ssl_context(*, insecure=False):
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=certifi.where())


def download(key, output, *, insecure=False):
    if "://" in key or key.startswith(("/", "\\")) or ".." in key.split("/"):
        raise ValueError("Invalid object key")
    url = "https://download.tplinkcloud.com/" + urllib.parse.quote(
        key, safe="/[]_-()."
    )
    return download_url(url, output, insecure=insecure)


def download_url(url, output, *, insecure=False):
    if "...." in url or "<" in url or ">" in url:
        raise ValueError(
            "Refusing placeholder firmware URL. Supply an exact URL returned "
            "by camera metadata or a verified historical source."
        )
    low = url.lower()
    if not low.startswith((
        "https://download.tplinkcloud.com/",
        "http://download.tplinkcloud.com/",
    )):
        raise ValueError(
            "Only download.tplinkcloud.com firmware URLs are accepted"
        )
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "V5PatchLab/1.0.11"},
    )
    kwargs = {"timeout": 60}
    if low.startswith("https://"):
        kwargs["context"] = _ssl_context(insecure=insecure)

    with urllib.request.urlopen(req, **kwargs) as r, out.open("wb") as f:
        while True:
            b = r.read(1024 * 1024)
            if not b:
                break
            f.write(b)

    from .evidence import sha256_file
    return {
        "url": url,
        "output": str(out),
        "size": out.stat().st_size,
        "sha256": sha256_file(out),
        "tls": {
            "verification": not insecure,
            "ca_bundle": None if insecure else certifi.where(),
            "mode": "INSECURE_EXPLICIT" if insecure else "CERTIFI",
        },
    }
