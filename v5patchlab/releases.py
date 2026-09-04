from __future__ import annotations
import re
import urllib.request

URL = "https://www.tp-link.com/fr/support/download/tapo-c200/v5/"
PAT = re.compile(
    r"Tapo C200\(EU\)_V5_(\d+\.\d+\.\d+)\s+Build\s+(\d{6})",
    re.I,
)

def fetch_official_releases():
    req = urllib.request.Request(
        URL,
        headers={
            "User-Agent": "Mozilla/5.0 V5PatchLab/1.0.2",
            "Accept": "text/html,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", errors="replace")
    rows = []
    seen = set()
    for m in PAT.finditer(text):
        key = (m.group(1), m.group(2))
        if key in seen:
            continue
        seen.add(key)
        rows.append({"version": key[0], "build": key[1]})
    return {"source": URL, "releases": rows}
