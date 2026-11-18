"""The peers' decision journal: one JSON object per line, appended by every chain peer.

Response bodies must not reveal which authentication check failed (http-signature-08 s3.6), so the precise cause of a
refusal is recorded here instead, and the chain driver reads the cause from this file, the way peers/driver.py reads
Maurice's journal. The file is WIMSE_JOURNAL_FILE if set, otherwise runs/peer-decisions.jsonl (git-ignored).
"""
import json
import os
import pathlib
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
_LOCK = threading.Lock()


def path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("WIMSE_JOURNAL_FILE") or ROOT / "runs" / "peer-decisions.jsonl")


def append(entry: dict) -> None:
    p = path()
    try:
        with _LOCK:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # a journal that cannot be written must not change a decision


def size() -> int:
    try:
        return path().stat().st_size
    except OSError:
        return 0


def read_since(offset: int) -> list[dict]:
    """Entries appended after byte `offset` (from size())."""
    try:
        with path().open("rb") as f:
            f.seek(offset)
            data = f.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for line in data.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
