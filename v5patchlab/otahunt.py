from __future__ import annotations

import hashlib
import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .evidence import stamp, write_json


SUPPORT_PAGES = [
    "https://www.tp-link.com/fr/support/download/tapo-c200/v5/",
    "https://www.tp-link.com/en/support/download/tapo-c200/v5/",
    "https://www.tp-link.com/us/support/download/tapo-c200/v5/",
]

PUBLIC_REFERENCE_SOURCES = [
    {
        "name": "haswira-tapofirmware-index-2025",
        "url": "https://raw.githubusercontent.com/haswira/tapofirmware/main/firmware29nov25.txt",
        "purpose": "Historical public firmware-object index; useful for path/name grammar.",
    },
    {
        "name": "jonathanuhler-firmware-download-notes",
        "url": (
            "https://raw.githubusercontent.com/JonathanUhler/H110-Security/main/"
            "research/notes/2026-08-21_Firmware-Downloads/Summary.md"
        ),
        "purpose": "Public research notes about TP-Link firmware object paths.",
    },
]

ALLOWED_VALIDATION_HOSTS = {
    "download.tplinkcloud.com",
    "static.tp-link.com",
    "static.tp-linkcloud.com",
    "www.tp-link.com",
    "static-product.tp-link.com",
    "web.archive.org",
}

URL_RE = re.compile(r"""(?P<url>https?:(?://|\\/\\/)[^\s"'<>\\]+)""", re.I)
HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value[:140].strip("._") or "source"


def fetch_bytes(url, *, timeout=20.0, max_bytes=8*1024*1024, headers=None):
    req_headers = {
        "User-Agent": "Mozilla/5.0 V5PatchLab/1.0.8",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return {
            "url": r.geturl(),
            "status": getattr(r, "status", 200),
            "content_type": r.headers.get("Content-Type"),
            "content_length_header": r.headers.get("Content-Length"),
            "last_modified": r.headers.get("Last-Modified"),
            "etag": r.headers.get("ETag"),
            "data": data,
            "truncated": truncated,
        }


def decode_text(data: bytes, content_type=None) -> str:
    charset = None
    if content_type:
        m = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.I)
        if m:
            charset = m.group(1)
    for enc in [charset, "utf-8", "latin-1"]:
        if not enc:
            continue
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return data.decode("utf-8", errors="replace")


def normalized_text(text: str) -> str:
    text = html.unescape(text)
    return text.replace(r"https:\/\/", "https://").replace(
        r"http:\/\/", "http://"
    ).replace(r"\/", "/")


def token_set(version, build, rel):
    tokens = {
        version, build, version.replace(".", "_"),
        f"Build {build}", f"Build_{build}",
    }
    if rel:
        rel_clean = rel if rel.lower().startswith("rel.") else f"Rel.{rel}"
        tokens.update({
            rel, rel_clean,
            rel_clean.replace(".", "_"),
            rel_clean.replace(".", ""),
        })
    return sorted(x for x in tokens if x)


def find_snippets(text, tokens: Iterable[str], radius=650):
    low = text.lower()
    rows, seen = [], set()
    for token in tokens:
        pos, needle = 0, token.lower()
        while True:
            i = low.find(needle, pos)
            if i < 0:
                break
            snippet = text[max(0, i-radius):min(len(text), i+len(token)+radius)]
            digest = hashlib.sha256(snippet.encode("utf-8", errors="replace")).hexdigest()
            if digest not in seen:
                seen.add(digest)
                rows.append({
                    "token": token,
                    "offset": i,
                    "snippet": snippet,
                    "snippet_sha256": digest,
                })
            pos = i + max(1, len(token))
            if len(rows) >= 200:
                return rows
    return rows


def extract_urls(text, base_url=None):
    text = normalized_text(text)
    candidates = []
    for m in URL_RE.finditer(text):
        candidates.append(m.group("url").replace(r"\/", "/").rstrip(".,);]}"))
    for raw in HREF_RE.findall(text):
        raw = html.unescape(raw).replace(r"\/", "/")
        if base_url:
            raw = urllib.parse.urljoin(base_url, raw)
        if raw.lower().startswith(("http://", "https://")):
            candidates.append(raw)
    out, seen = [], set()
    for url in candidates:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def interesting_url(url, tokens):
    low = url.lower()
    return (
        any(t.lower() in low for t in tokens)
        or "firmware" in low
        or low.endswith((".bin", ".bin.release", ".zip", ".img", ".fw"))
        or "download" in low
    )


def candidate_contexts(text, urls, tokens):
    norm, low = normalized_text(text), normalized_text(text).lower()
    tokens = list(tokens)
    token_low = [x.lower() for x in tokens]
    rows = []
    for url in urls:
        i = low.find(url.lower())
        if i < 0:
            rows.append({"url": url, "near_target_token": False, "matched_tokens": []})
            continue
        win = low[max(0, i-1800):min(len(low), i+len(url)+1800)]
        matched = [a for a, b in zip(tokens, token_low) if b in win]
        rows.append({
            "url": url,
            "near_target_token": bool(matched),
            "matched_tokens": matched,
        })
    return rows


def save_source(run_dir, name, result):
    p = run_dir / "sources" / f"{safe_name(name)}.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"URL: {result.get('url')}\nHTTP: {result.get('status')}\n"
        f"Content-Type: {result.get('content_type')}\n"
        f"Truncated: {result.get('truncated')}\n"
        f"SHA256: {sha256_bytes(result.get('data') or b'')}\n\n"
    ).encode()
    p.write_bytes(header + (result.get("data") or b""))
    return str(p)


def scan_source(*, name, url, tokens, run_dir, max_bytes=8*1024*1024):
    try:
        r = fetch_bytes(url, max_bytes=max_bytes)
        text = normalized_text(decode_text(r["data"], r.get("content_type")))
        urls = [x for x in extract_urls(text, r["url"]) if interesting_url(x, tokens)]
        return {
            "name": name,
            "requested_url": url,
            "final_url": r["url"],
            "ok": True,
            "status": r["status"],
            "bytes": len(r["data"]),
            "truncated": r["truncated"],
            "sha256": sha256_bytes(r["data"]),
            "saved": save_source(run_dir, name, r),
            "target_snippets": find_snippets(text, tokens),
            "interesting_urls": candidate_contexts(text, urls, tokens),
        }
    except Exception as exc:
        return {
            "name": name,
            "requested_url": url,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "target_snippets": [],
            "interesting_urls": [],
        }


def wayback_cdx(original_url, *, from_date=None, to_date=None, limit=50):
    params = {
        "url": original_url,
        "output": "json",
        "fl": "timestamp,original,statuscode,digest,mimetype",
        "filter": "statuscode:200",
        "collapse": "digest",
        "limit": str(limit),
    }
    if from_date:
        params["from"] = re.sub(r"\D", "", from_date)
    if to_date:
        params["to"] = re.sub(r"\D", "", to_date)
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    r = fetch_bytes(url, max_bytes=4*1024*1024)
    obj = json.loads(decode_text(r["data"], r.get("content_type")))
    if not obj:
        return {"query_url": url, "rows": []}
    header = obj[0]
    return {"query_url": url, "rows": [dict(zip(header, row)) for row in obj[1:]]}


def nearest_snapshots(rows, release_date, limit=8):
    if not rows:
        return []
    target = datetime.strptime(release_date[:10], "%Y-%m-%d")
    def distance(row):
        try:
            d = datetime.strptime(str(row.get("timestamp") or "")[:8], "%Y%m%d")
            return abs((d-target).days)
        except ValueError:
            return 10**9
    return sorted(rows, key=distance)[:limit]


def scan_wayback_support(*, page_url, release_date, tokens, run_dir):
    release = datetime.strptime(release_date[:10], "%Y-%m-%d")
    from_date = f"{release.year}{max(1, release.month-2):02d}01"
    to_date = f"{release.year}{min(12, release.month+3):02d}31"
    try:
        cdx = wayback_cdx(page_url, from_date=from_date, to_date=to_date, limit=100)
    except Exception as exc:
        return {"support_url": page_url, "ok": False, "error": str(exc), "snapshots": []}
    snaps = []
    for row in nearest_snapshots(cdx["rows"], release_date, 10):
        snap_url = f"https://web.archive.org/web/{row['timestamp']}id_/{row['original']}"
        snaps.append(scan_source(
            name=f"wayback-{row['timestamp']}-{urllib.parse.urlparse(page_url).netloc}",
            url=snap_url,
            tokens=tokens,
            run_dir=run_dir,
            max_bytes=4*1024*1024,
        ))
    return {
        "support_url": page_url,
        "ok": True,
        "cdx_query": cdx["query_url"],
        "cdx_rows": len(cdx["rows"]),
        "snapshots": snaps,
    }


def scan_wayback_firmware_index(*, version, build, rel):
    searches = [("build", build), ("version", version)]
    if rel:
        searches.append(("rel", rel))
    results = []
    for label, token in searches:
        params = [
            ("url", "download.tplinkcloud.com/firmware/*"),
            ("output", "json"),
            ("fl", "timestamp,original,statuscode,digest,mimetype"),
            ("filter", "statuscode:200"),
            ("filter", f"original:.*{re.escape(token)}.*"),
            ("collapse", "urlkey"),
            ("limit", "200"),
        ]
        q = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
        try:
            r = fetch_bytes(q, max_bytes=4*1024*1024)
            obj = json.loads(decode_text(r["data"], r.get("content_type")))
            rows = []
            if obj:
                header = obj[0]
                rows = [dict(zip(header, x)) for x in obj[1:]]
            results.append({"label": label, "token": token, "query_url": q, "ok": True, "rows": rows})
        except Exception as exc:
            results.append({"label": label, "token": token, "query_url": q, "ok": False, "error": str(exc), "rows": []})
    return results


def github_code_search(*, version, build, rel):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return {"enabled": False, "reason": "GITHUB_TOKEN not set", "queries": []}
    queries = [f'"{build}" "Tapo C200"', f'"{version}" "download.tplinkcloud.com"']
    if rel:
        queries.append(f'"{rel}"')
    rows = []
    for q in queries:
        url = "https://api.github.com/search/code?" + urllib.parse.urlencode({"q": q, "per_page": 50})
        try:
            r = fetch_bytes(url, max_bytes=4*1024*1024, headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            })
            obj = json.loads(decode_text(r["data"]))
            rows.append({
                "query": q,
                "ok": True,
                "total_count": obj.get("total_count"),
                "items": [{
                    "name": x.get("name"),
                    "path": x.get("path"),
                    "html_url": x.get("html_url"),
                    "repository": (x.get("repository") or {}).get("full_name"),
                } for x in obj.get("items", [])],
            })
        except Exception as exc:
            rows.append({"query": q, "ok": False, "error": str(exc), "items": []})
    return {"enabled": True, "token_logged": False, "queries": rows}


def validate_url(url):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host not in ALLOWED_VALIDATION_HOSTS:
        return {"url": url, "ok": False, "refused": True, "reason": f"Host not allowlisted: {host}"}
    head = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "V5PatchLab/1.0.8"})
    try:
        with urllib.request.urlopen(head, timeout=15) as r:
            return {
                "url": url, "ok": True, "method": "HEAD",
                "status": getattr(r, "status", 200), "final_url": r.geturl(),
                "content_type": r.headers.get("Content-Type"),
                "content_length": r.headers.get("Content-Length"),
                "etag": r.headers.get("ETag"),
                "last_modified": r.headers.get("Last-Modified"),
            }
    except Exception as exc:
        head_error = f"{type(exc).__name__}: {exc}"
    try:
        r = fetch_bytes(url, timeout=15, max_bytes=4096, headers={"Range": "bytes=0-4095"})
        return {
            "url": url, "ok": True, "method": "GET Range 0-4095",
            "status": r["status"], "final_url": r["url"],
            "content_type": r.get("content_type"),
            "sample_len": len(r["data"]),
            "sample_sha256": sha256_bytes(r["data"]),
            "sample_prefix_hex": r["data"][:32].hex(),
            "head_error": head_error,
        }
    except Exception as exc:
        return {
            "url": url, "ok": False, "method": "HEAD + GET Range",
            "head_error": head_error, "error": f"{type(exc).__name__}: {exc}",
        }


def collect_candidates(result):
    found = {}
    def add(url, source, confidence, matched=None):
        if not url or not url.lower().startswith(("http://", "https://")):
            return
        row = found.setdefault(url, {"url": url, "sources": [], "confidence": confidence, "matched_tokens": set()})
        row["sources"].append(source)
        if confidence == "target-nearby":
            row["confidence"] = "target-nearby"
        row["matched_tokens"].update(x for x in (matched or []) if x)

    for source in result.get("live_support", []):
        for row in source.get("interesting_urls", []):
            add(row["url"], source["name"], "target-nearby" if row["near_target_token"] else "generic", row.get("matched_tokens"))
    for wb in result.get("wayback_support", []):
        for snap in wb.get("snapshots", []):
            for row in snap.get("interesting_urls", []):
                add(row["url"], snap["name"], "target-nearby" if row["near_target_token"] else "generic", row.get("matched_tokens"))
    for group in result.get("wayback_firmware_index", []):
        for row in group.get("rows", []):
            add(row.get("original"), f"wayback-cdx-{group.get('label')}", "target-nearby", [group.get("token")])
    for ref in result.get("public_reference_sources", []):
        for row in ref.get("interesting_urls", []):
            add(row["url"], ref["name"], "target-nearby" if row["near_target_token"] else "generic", row.get("matched_tokens"))

    rows = []
    for row in found.values():
        row["matched_tokens"] = sorted(row["matched_tokens"])
        row["sources"] = sorted(set(row["sources"]))
        rows.append(row)
    return sorted(rows, key=lambda r: (
        r["confidence"] != "target-nearby",
        "download.tplinkcloud.com" not in r["url"].lower(),
        r["url"],
    ))


def run_ota_hunt(*, version, build, rel, release_date, region="EU",
                 evidence_base="evidence/runs", wayback=True, validate=True):
    tokens = token_set(version, build, rel)
    run_dir = Path(evidence_base) / f"{stamp()}-ota-hunt-{build}"
    run_dir.mkdir(parents=True, exist_ok=False)
    result = {
        "target": {
            "product": "Tapo C200 V5", "region": region,
            "version": version, "build": build, "rel": rel,
            "release_date": release_date, "tokens": tokens,
        },
        "started_at": utcnow(),
        "live_support": [], "wayback_support": [],
        "wayback_firmware_index": [], "public_reference_sources": [],
        "github_code_search": None, "candidates": [], "validations": [],
        "evidence": {"directory": str(run_dir), "result_json": str(run_dir/"result.json")},
        "scope_note": "Public-source metadata only; no camera mutation or object-key brute force.",
    }
    for page in SUPPORT_PAGES:
        slug = urllib.parse.urlparse(page).path.split("/")[1]
        result["live_support"].append(scan_source(
            name=f"live-support-{slug}", url=page, tokens=tokens,
            run_dir=run_dir, max_bytes=4*1024*1024,
        ))
    if wayback:
        for page in SUPPORT_PAGES:
            result["wayback_support"].append(scan_wayback_support(
                page_url=page, release_date=release_date,
                tokens=tokens, run_dir=run_dir,
            ))
        result["wayback_firmware_index"] = scan_wayback_firmware_index(
            version=version, build=build, rel=rel
        )
    for ref in PUBLIC_REFERENCE_SOURCES:
        row = scan_source(
            name=ref["name"], url=ref["url"], tokens=tokens,
            run_dir=run_dir, max_bytes=8*1024*1024,
        )
        row["purpose"] = ref["purpose"]
        result["public_reference_sources"].append(row)
    result["github_code_search"] = github_code_search(version=version, build=build, rel=rel)
    result["candidates"] = collect_candidates(result)
    if validate:
        for row in result["candidates"][:80]:
            if row["confidence"] == "target-nearby" or "download.tplinkcloud.com" in row["url"].lower():
                check = validate_url(row["url"])
                check.update({
                    "candidate_confidence": row["confidence"],
                    "sources": row["sources"],
                    "matched_tokens": row["matched_tokens"],
                })
                result["validations"].append(check)
    exact = [
        x for x in result["validations"]
        if x.get("ok")
        and x.get("candidate_confidence") == "target-nearby"
        and "download.tplinkcloud.com" in x["url"].lower()
    ]
    result["interpretation"] = {
        "target_candidate_count": sum(c["confidence"] == "target-nearby" for c in result["candidates"]),
        "validated_candidate_count": sum(bool(x.get("ok")) for x in result["validations"]),
        "validated_target_tplinkcloud_count": len(exact),
        "exact_ota_url_candidates": [x["url"] for x in exact],
        "next": (
            "Validate/download exact candidate and feed it to decrypt."
            if exact else
            "No exact OTA object recovered; preserve result.json and expand indexed sources without inventing timestamp suffixes."
        ),
    }
    result["finished_at"] = utcnow()
    write_json(run_dir/"result.json", result)
    return result


def scan_local_file(*, path, version, build, rel):
    p = Path(path)
    data = p.read_bytes()
    text = normalized_text(decode_text(data))
    tokens = token_set(version, build, rel)
    urls = [x for x in extract_urls(text) if interesting_url(x, tokens)]
    return {
        "path": str(p), "size": len(data), "sha256": sha256_bytes(data),
        "target_snippets": find_snippets(text, tokens),
        "interesting_urls": candidate_contexts(text, urls, tokens),
    }
