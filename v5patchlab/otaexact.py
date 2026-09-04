from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .evidence import stamp, write_json


PRODUCT = "Tapo_C200v5"
CDN = "https://download.tplinkcloud.com/"

RIPTHULHU_REPO = "https://github.com/Ripthulhu/tp-link-tapo-firmware"
RIPTHULHU_RAW = (
    "https://raw.githubusercontent.com/"
    "Ripthulhu/tp-link-tapo-firmware/main/"
)

INDEX_SOURCES = [
    {
        "name": "ripthulhu-all-firmware",
        "url": RIPTHULHU_RAW + "all_firmware.txt",
        "snapshot_note": (
            "Public bucket-object snapshot. Repository was created/pushed "
            "2026-06-23, so absence of a later July 2026 build is expected."
        ),
    },
    {
        "name": "ripthulhu-tapo-firmware",
        "url": RIPTHULHU_RAW + "tapo_firmware.txt",
        "snapshot_note": (
            "Tapo-focused public bucket listing from the same 2026-06-23 repo."
        ),
    },
    {
        "name": "ripthulhu-tapo-csv",
        "url": RIPTHULHU_RAW + "tapo_firmware.csv",
        "snapshot_note": (
            "CSV metadata/index from the same public bucket snapshot."
        ),
    },
]

WAYBACK_HOSTS = {"web.archive.org", "web.archive.org."}

OBJECT_RE = re.compile(
    r"""(?P<key>
        firmware/
        (?:assigned/)?
        Tapo_C200v5
        [^\s"'<>]*
        \.bin(?:\.rollback)?
    )""",
    re.I | re.X,
)

FULL_URL_RE = re.compile(
    r"""https?://download\.tplinkcloud\.com/
        (?P<key>firmware/[^\s"'<>]+)
    """,
    re.I | re.X,
)

FW_RE = re.compile(
    r"""Tapo_C200v5
        (?:_[A-Za-z0-9.-]+)?
        _en_
        (?P<version>\d+\.\d+\.\d+)
        _Build_(?P<build>\d+)
        _Rel[._](?P<rel>[A-Za-z0-9]+)
    """,
    re.I | re.X,
)

LINE_META_RE = re.compile(
    r"""^\s*
        (?:(?P<date>\d{4}-\d{2}-\d{2})
           [ T]
           (?P<time>\d{2}:\d{2}:\d{2})
           \s+)?
        (?:(?P<size>\d+)\s+)?
        (?P<rest>.*?)
        \s*$
    """,
    re.X,
)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def safe_name(value: str):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:160].strip("._") or "source"


def _certifi_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where()), certifi.where()
    except Exception:
        return None, None


def make_ssl_context(*, ca_bundle=None, insecure=False):
    if insecure:
        return ssl._create_unverified_context(), {
            "mode": "INSECURE_EXPLICIT",
            "verification": False,
            "ca_bundle": None,
        }

    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle), {
            "mode": "EXPLICIT_CA_BUNDLE",
            "verification": True,
            "ca_bundle": ca_bundle,
        }

    ctx, path = _certifi_context()
    if ctx is not None:
        return ctx, {
            "mode": "CERTIFI",
            "verification": True,
            "ca_bundle": path,
        }

    return ssl.create_default_context(), {
        "mode": "SYSTEM_DEFAULT",
        "verification": True,
        "ca_bundle": None,
    }


def fetch_bytes(
    url,
    *,
    max_bytes=4 * 1024 * 1024,
    timeout=25,
    ca_bundle=None,
    insecure=False,
    headers=None,
):
    ctx, tls = make_ssl_context(
        ca_bundle=ca_bundle,
        insecure=insecure,
    )
    req_headers = {
        "User-Agent": "Mozilla/5.0 V5PatchLab/1.0.9",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        data = r.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return {
            "requested_url": url,
            "final_url": r.geturl(),
            "status": getattr(r, "status", 200),
            "content_type": r.headers.get("Content-Type"),
            "content_length": r.headers.get("Content-Length"),
            "etag": r.headers.get("ETag"),
            "last_modified": r.headers.get("Last-Modified"),
            "data": data,
            "truncated": truncated,
            "tls": tls,
        }


def _decode(data):
    return data.decode("utf-8", errors="replace")


def _normalize_key(key):
    key = key.strip().strip("`'\".,);]}")
    key = key.replace("\\/", "/")
    if key.startswith(CDN):
        key = key[len(CDN):]
    return key


def object_url(key):
    key = _normalize_key(key)
    return CDN + urllib.parse.quote(key, safe="/[]_-().")


def parse_object(key, *, raw_line=None, source=None, date=None, size=None):
    key = _normalize_key(key)
    m = FW_RE.search(key)
    if not m:
        return None

    rel = m.group("rel")
    if not rel.lower().endswith("n") and "Rel." in key:
        # Preserve exact value. Some non-camera products use Rel without n,
        # but C200 camera keys normally carry n.
        pass

    suffix_epoch = None
    em = re.search(r"_(\d{12,16})\.bin(?:\.rollback)?$", key, re.I)
    if em:
        suffix_epoch = em.group(1)

    return {
        "product": PRODUCT,
        "version": m.group("version"),
        "build": m.group("build"),
        "rel": rel,
        "key": key,
        "url": object_url(key),
        "assigned": key.lower().startswith("firmware/assigned/"),
        "rollback": key.lower().endswith(".rollback"),
        "epoch_suffix": suffix_epoch,
        "source": source,
        "date": date,
        "size": int(size) if size and str(size).isdigit() else None,
        "raw_line": raw_line,
    }


def parse_index_text(text, *, source):
    rows = []
    seen = set()

    for raw in text.splitlines():
        line = raw.strip()
        if PRODUCT.lower() not in line.lower():
            continue

        lm = LINE_META_RE.match(line)
        date = lm.group("date") if lm else None
        size = lm.group("size") if lm else None

        candidates = []

        for um in FULL_URL_RE.finditer(line):
            candidates.append(um.group("key"))

        for km in OBJECT_RE.finditer(line):
            candidates.append(km.group("key"))

        # A URL list may contain escaped or percent-encoded paths.
        try:
            decoded = urllib.parse.unquote(line)
        except Exception:
            decoded = line
        if decoded != line:
            for km in OBJECT_RE.finditer(decoded):
                candidates.append(km.group("key"))

        for key in candidates:
            obj = parse_object(
                key,
                raw_line=raw,
                source=source,
                date=date,
                size=size,
            )
            if obj and obj["key"] not in seen:
                seen.add(obj["key"])
                rows.append(obj)

    return rows


def target_match(row, *, version, build, rel):
    exact_build = row["build"] == str(build)
    exact_version = row["version"] == str(version)
    want_rel = str(rel or "").lower().removeprefix("rel.")
    got_rel = str(row["rel"] or "").lower().removeprefix("rel.")
    exact_rel = (not want_rel) or got_rel == want_rel
    return exact_build and exact_version and exact_rel


def nearby_inventory(rows, *, build, limit=20):
    def build_int(row):
        try:
            return int(row["build"])
        except Exception:
            return 0

    target = int(build)
    product_rows = sorted(
        rows,
        key=lambda r: abs(build_int(r) - target),
    )

    out = []
    seen = set()
    for row in product_rows:
        sig = (row["version"], row["build"], row["rel"], row["key"])
        if sig in seen:
            continue
        seen.add(sig)
        out.append({
            "version": row["version"],
            "build": row["build"],
            "rel": row["rel"],
            "key": row["key"],
            "date": row.get("date"),
            "size": row.get("size"),
            "source": row.get("source"),
        })
        if len(out) >= limit:
            break
    return out


def scan_public_indexes(
    *,
    version,
    build,
    rel,
    run_dir,
    ca_bundle=None,
):
    sources = []
    all_rows = []

    for src in INDEX_SOURCES:
        record = {
            "name": src["name"],
            "url": src["url"],
            "snapshot_note": src["snapshot_note"],
        }
        try:
            r = fetch_bytes(
                src["url"],
                max_bytes=3 * 1024 * 1024,
                ca_bundle=ca_bundle,
            )
            text = _decode(r["data"])
            rows = parse_index_text(text, source=src["name"])
            exact = [
                x for x in rows
                if target_match(
                    x,
                    version=version,
                    build=build,
                    rel=rel,
                )
            ]

            saved = run_dir / "sources" / f"{safe_name(src['name'])}.txt"
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(r["data"])

            record.update({
                "ok": True,
                "status": r["status"],
                "bytes": len(r["data"]),
                "sha256": sha256_bytes(r["data"]),
                "tls": r["tls"],
                "saved": str(saved),
                "c200v5_object_count": len(rows),
                "exact_matches": exact,
            })
            all_rows.extend(rows)
        except Exception as exc:
            record.update({
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "exact_matches": [],
            })

        sources.append(record)

    dedup = {}
    for row in all_rows:
        dedup[row["key"]] = row
    all_rows = list(dedup.values())

    exact = [
        row for row in all_rows
        if target_match(
            row,
            version=version,
            build=build,
            rel=rel,
        )
    ]

    return {
        "sources": sources,
        "all_c200v5_objects": all_rows,
        "exact_matches": exact,
        "nearby_inventory": nearby_inventory(
            all_rows,
            build=build,
        ),
    }


def _parse_list_xml(raw, source_name):
    root = ET.fromstring(raw)
    rows = []
    for c in root.findall(".//{*}Contents"):
        key = c.findtext("{*}Key") or c.findtext("Key")
        if not key:
            continue
        if PRODUCT.lower() not in key.lower():
            continue

        obj = parse_object(
            key,
            source=source_name,
            date=(
                c.findtext("{*}LastModified")
                or c.findtext("LastModified")
            ),
            size=(
                c.findtext("{*}Size")
                or c.findtext("Size")
            ),
        )
        if obj:
            rows.append(obj)

    next_token = (
        root.findtext(".//{*}NextContinuationToken")
        or root.findtext(".//NextContinuationToken")
    )
    truncated = (
        root.findtext(".//{*}IsTruncated")
        or root.findtext(".//IsTruncated")
        or ""
    ).strip().lower() == "true"

    return rows, truncated, next_token


def live_bucket_prefix_queries(
    *,
    version,
    build,
    rel,
    ca_bundle=None,
):
    # These are prefix-list requests only: exact product/build prefixes.
    # No suffix/timestamp guessing.
    rel_clean = str(rel or "").removeprefix("Rel.")
    prefixes = [
        (
            "exact-version-build-rel",
            f"firmware/assigned/{PRODUCT}_en_{version}_Build_{build}_Rel.{rel_clean}",
        ),
        (
            "exact-version-build",
            f"firmware/assigned/{PRODUCT}_en_{version}_Build_{build}",
        ),
        (
            "product-assigned",
            f"firmware/assigned/{PRODUCT}",
        ),
    ]

    endpoints = [
        ("cdn-virtual-host", "https://download.tplinkcloud.com/"),
        (
            "s3-path-style",
            "https://s3.amazonaws.com/download.tplinkcloud.com/",
        ),
    ]

    attempts = []
    exact = []
    inventory = []

    for endpoint_name, base in endpoints:
        for label, prefix in prefixes:
            params = urllib.parse.urlencode({
                "list-type": "2",
                "prefix": prefix,
                "max-keys": "1000",
            })
            url = base + "?" + params
            rec = {
                "endpoint": endpoint_name,
                "label": label,
                "prefix": prefix,
                "url": url,
            }

            try:
                r = fetch_bytes(
                    url,
                    max_bytes=4 * 1024 * 1024,
                    ca_bundle=ca_bundle,
                )
                rows, truncated, next_token = _parse_list_xml(
                    r["data"],
                    f"live-bucket:{endpoint_name}:{label}",
                )
                rec.update({
                    "ok": True,
                    "status": r["status"],
                    "bytes": len(r["data"]),
                    "tls": r["tls"],
                    "rows": rows,
                    "is_truncated": truncated,
                    "next_continuation_token_present": bool(next_token),
                })
                inventory.extend(rows)
                exact.extend(
                    row for row in rows
                    if target_match(
                        row,
                        version=version,
                        build=build,
                        rel=rel,
                    )
                )

                # Exact prefix should fit in one page. We deliberately do not
                # crawl an unbounded bucket.
                if label == "exact-version-build-rel" and truncated and next_token:
                    rec["note"] = (
                        "Exact prefix is truncated; continuation not followed "
                        "automatically to preserve bounded behavior."
                    )
            except urllib.error.HTTPError as exc:
                body = b""
                try:
                    body = exc.read(4096)
                except Exception:
                    pass
                rec.update({
                    "ok": False,
                    "http_status": exc.code,
                    "error": f"HTTPError: {exc}",
                    "body_sample": body.decode("utf-8", errors="replace"),
                })
            except Exception as exc:
                rec.update({
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })

            attempts.append(rec)

            # If an exact target is found, there is no value in broader
            # product listing at the other endpoint.
            if exact:
                break

        if exact:
            break

    dedup_exact = {row["key"]: row for row in exact}
    dedup_inv = {row["key"]: row for row in inventory}

    return {
        "attempts": attempts,
        "exact_matches": list(dedup_exact.values()),
        "inventory": list(dedup_inv.values()),
    }



def wayback_cdx_exact(
    *,
    version,
    build,
    rel,
    ca_bundle=None,
    wayback_insecure=False,
):
    # Exact object-family prefix. This is materially cheaper for CDX than
    # regex filters over the entire firmware namespace and avoids the 503s
    # observed with the v1.0.9 query.
    prefix = (
        f"download.tplinkcloud.com/firmware/assigned/"
        f"{PRODUCT}_en_{version}_Build_{build}"
    )
    params = [
        ("url", prefix),
        ("matchType", "prefix"),
        ("output", "json"),
        ("fl", "timestamp,original,statuscode,digest,mimetype"),
        ("filter", "statuscode:200"),
        ("collapse", "urlkey"),
        ("limit", "200"),
    ]

    url = (
        "https://web.archive.org/cdx/search/cdx?"
        + urllib.parse.urlencode(params)
    )

    try:
        r = fetch_bytes(
            url,
            max_bytes=4 * 1024 * 1024,
            ca_bundle=ca_bundle,
            insecure=wayback_insecure,
        )
        obj = json.loads(_decode(r["data"]))
        rows = []
        if obj:
            header = obj[0]
            rows = [
                dict(zip(header, x))
                for x in obj[1:]
            ]

        candidates = []
        for row in rows:
            original = row.get("original")
            if not original:
                continue
            parsed = parse_object(
                original,
                source="wayback-cdx-prefix",
                date=row.get("timestamp"),
            )
            if parsed:
                candidates.append(parsed)

        exact = [
            x for x in candidates
            if target_match(
                x,
                version=version,
                build=build,
                rel=rel,
            )
        ]

        return {
            "ok": True,
            "query_url": url,
            "query_mode": "prefix",
            "query_prefix": prefix,
            "tls": r["tls"],
            "rows": rows,
            "parsed_candidates": candidates,
            "exact_matches": exact,
        }
    except Exception as exc:
        return {
            "ok": False,
            "query_url": url,
            "query_mode": "prefix",
            "query_prefix": prefix,
            "error": f"{type(exc).__name__}: {exc}",
            "exact_matches": [],
        }


def validate_candidate(url, *, ca_bundle=None):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host != "download.tplinkcloud.com":
        return {
            "url": url,
            "ok": False,
            "refused": True,
            "reason": "Only exact download.tplinkcloud.com candidates accepted",
        }

    ctx, tls = make_ssl_context(ca_bundle=ca_bundle)
    req = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "V5PatchLab/1.0.9"},
    )

    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return {
                "url": url,
                "ok": True,
                "method": "HEAD",
                "status": getattr(r, "status", 200),
                "final_url": r.geturl(),
                "content_type": r.headers.get("Content-Type"),
                "content_length": r.headers.get("Content-Length"),
                "etag": r.headers.get("ETag"),
                "last_modified": r.headers.get("Last-Modified"),
                "tls": tls,
            }
    except Exception as head_exc:
        try:
            r = fetch_bytes(
                url,
                max_bytes=4096,
                ca_bundle=ca_bundle,
                headers={"Range": "bytes=0-4095"},
            )
            return {
                "url": url,
                "ok": True,
                "method": "GET Range 0-4095",
                "status": r["status"],
                "final_url": r["final_url"],
                "content_type": r.get("content_type"),
                "sample_len": len(r["data"]),
                "sample_sha256": sha256_bytes(r["data"]),
                "sample_prefix_hex": r["data"][:32].hex(),
                "head_error": (
                    f"{type(head_exc).__name__}: {head_exc}"
                ),
                "tls": r["tls"],
            }
        except Exception as get_exc:
            return {
                "url": url,
                "ok": False,
                "head_error": (
                    f"{type(head_exc).__name__}: {head_exc}"
                ),
                "get_error": (
                    f"{type(get_exc).__name__}: {get_exc}"
                ),
            }


def run_exact_hunt(
    *,
    version,
    build,
    rel,
    release_date,
    evidence_base="evidence/runs",
    ca_bundle=None,
    wayback_insecure=False,
    live_bucket=True,
    validate=True,
):
    run_dir = (
        Path(evidence_base)
        / f"{stamp()}-ota-exact-{build}"
    )
    run_dir.mkdir(parents=True, exist_ok=False)

    public_indexes = scan_public_indexes(
        version=version,
        build=build,
        rel=rel,
        run_dir=run_dir,
        ca_bundle=ca_bundle,
    )

    bucket = (
        live_bucket_prefix_queries(
            version=version,
            build=build,
            rel=rel,
            ca_bundle=ca_bundle,
        )
        if live_bucket
        else {
            "attempts": [],
            "exact_matches": [],
            "inventory": [],
            "disabled": True,
        }
    )

    wayback = wayback_cdx_exact(
        version=version,
        build=build,
        rel=rel,
        ca_bundle=ca_bundle,
        wayback_insecure=wayback_insecure,
    )

    found = {}
    for group in [
        public_indexes["exact_matches"],
        bucket["exact_matches"],
        wayback["exact_matches"],
    ]:
        for row in group:
            found[row["key"]] = row

    exact = list(found.values())
    validations = []
    if validate:
        for row in exact:
            validations.append(
                validate_candidate(
                    row["url"],
                    ca_bundle=ca_bundle,
                )
            )

    result = {
        "target": {
            "product": "Tapo C200 V5",
            "object_product": PRODUCT,
            "version": version,
            "build": str(build),
            "rel": rel,
            "release_date": release_date,
        },
        "started_at": utcnow(),
        "public_indexes": public_indexes,
        "live_bucket": bucket,
        "wayback_cdx_exact": wayback,
        "exact_matches": exact,
        "validations": validations,
        "evidence": {
            "directory": str(run_dir),
            "result_json": str(run_dir / "result.json"),
        },
        "interpretation": {
            "exact_object_key_count": len(exact),
            "validated_live_count": sum(
                bool(x.get("ok"))
                for x in validations
            ),
            "exact_urls": [x["url"] for x in exact],
            "wayback_failed_tls": (
                not wayback.get("ok")
                and "CERTIFICATE_VERIFY_FAILED"
                in str(wayback.get("error"))
            ),
            "wayback_insecure_used": bool(
                wayback.get("ok")
                and (wayback.get("tls") or {}).get("verification") is False
            ),
            "note": (
                "A public-index absence is not proof the object never existed. "
                "The Ripthulhu repo is a 2026-06-23 snapshot."
            ),
        },
        "finished_at": utcnow(),
    }

    if exact:
        result["interpretation"]["next"] = (
            "Download the validated exact object, then decrypt/extract/diff."
        )
    elif result["interpretation"]["wayback_failed_tls"]:
        result["interpretation"]["next"] = (
            "Install certifi or pass --ca-bundle. For public Wayback metadata "
            "only, --wayback-insecure is an explicit last-resort option."
        )
    else:
        result["interpretation"]["next"] = (
            "No exact object key recovered. Preserve this evidence; next "
            "acquisition route should use exact cloud metadata/fwId or a newer "
            "bucket snapshot, not timestamp guessing."
        )

    write_json(run_dir / "result.json", result)
    return result


def known_targets():
    return [
        {
            "version": "1.4.4",
            "build": "260527",
            "rel": "28339n",
            "release_date": "2026-06-02",
        },
        {
            "version": "1.4.6",
            "build": "260709",
            "rel": "27675n",
            "release_date": "2026-07-17",
        },
    ]
