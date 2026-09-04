from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

def utc_now(): return datetime.now(timezone.utc).isoformat()
def tag(): return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
def sha256(data: bytes): return hashlib.sha256(data).hexdigest()
def dump_json(path, obj):
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding='utf-8')

class EvidenceRun:
    def __init__(self, base, name):
        self.dir=Path(base)/f"{tag()}-{name}"; self.dir.mkdir(parents=True, exist_ok=False)
    def event(self, kind, **fields):
        row={'ts':utc_now(),'kind':kind,**fields}
        with (self.dir/'events.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str)+'\n')
        return row
    def finish(self, summary): dump_json(self.dir/'summary.json', summary)
