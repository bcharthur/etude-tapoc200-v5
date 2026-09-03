from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "evidence" / "runs"


def latest_pcap() -> Path | None:
    if not RUNS.exists():
        return None

    candidates = []
    for p in RUNS.iterdir():
        if not p.is_dir():
            continue
        capture = p / "capture.pcap"
        if capture.exists():
            candidates.append(capture)

    if not candidates:
        return None

    return sorted(
        candidates,
        key=lambda p: p.parent.name,
        reverse=True,
    )[0]


def resolve_pcap(value: str | None) -> Path:
    if value is None or value.lower() == "latest":
        p = latest_pcap()
        if p is None:
            raise FileNotFoundError(
                "Aucun capture.pcap trouvé dans evidence/runs."
            )
        return p

    p = Path(value)

    if p.is_file():
        return p

    if p.is_dir():
        candidate = p / "capture.pcap"
        if candidate.exists():
            return candidate
        raise FileNotFoundError(
            f"Le run {p} ne contient pas capture.pcap."
        )

    # Convenience: allow only the run id.
    candidate = RUNS / value / "capture.pcap"
    if candidate.exists():
        return candidate

    raise FileNotFoundError(
        f"PCAP introuvable: {value}. "
        "Utilise un fichier capture.pcap, un dossier de run, "
        "un identifiant de run, ou 'latest'."
    )
