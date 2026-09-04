from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_label(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return value.strip("-._") or "observe"


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")
        fh.flush()


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def load_env_file(path: str | Path | None) -> dict[str, str]:
    """Load KEY=VALUE pairs without requiring python-dotenv.

    Existing process environment variables win over values from the file.
    """
    loaded: dict[str, str] = {}
    if not path:
        return loaded
    p = Path(path)
    if not p.exists():
        return loaded
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


def sanitize_text(text: object, secrets: list[str] | tuple[str, ...] = ()) -> str:
    s = str(text)
    for secret in secrets:
        if secret:
            s = s.replace(secret, "<redacted>")
    # redact rtsp/http basic-auth style credentials in URLs
    s = re.sub(r"(rtsp|https?|rtsps)://[^/@\s:]+:[^/@\s]+@", r"\1://<redacted>@", s, flags=re.I)
    return s


def redact_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        userinfo = "<credentials>@" if parts.username is not None else ""
        return urlunsplit((parts.scheme, f"{userinfo}{host}{port}", parts.path, parts.query, parts.fragment))
    except Exception:
        return sanitize_text(url)


def build_rtsp_url(ip: str) -> str | None:
    explicit = os.getenv("TAPO_RTSP_URL", "").strip()
    if explicit:
        return explicit
    user = os.getenv("TAPO_RTSP_USER", "").strip()
    password = os.getenv("TAPO_RTSP_PASSWORD", "").strip()
    if not user or not password:
        return None
    path = os.getenv("TAPO_RTSP_PATH", "/stream2").strip() or "/stream2"
    if not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{quote(user, safe='')}:{quote(password, safe='')}@{ip}:554{path}"


def find_executable(name: str) -> str | None:
    hit = shutil.which(name)
    if hit:
        return hit
    if os.name == "nt":
        candidates = {
            "tshark": [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"],
            "dumpcap": [r"C:\Program Files\Wireshark\dumpcap.exe", r"C:\Program Files (x86)\Wireshark\dumpcap.exe"],
        }
        for candidate in candidates.get(name.lower(), []):
            if Path(candidate).exists():
                return candidate
    return None


def run_command(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as exc:
        return -1, "", f"{type(exc).__name__}: {exc}"


def monotonic() -> float:
    return time.monotonic()


def runtime_info() -> dict:
    return {
        "python": sys.version.replace("\n", " "),
        "platform": sys.platform,
        "pid": os.getpid(),
        "cwd": str(Path.cwd()),
    }
