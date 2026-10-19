"""Persistência das baselines: um JSON por host."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _path(directory: Path, host: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    return directory / f"{safe}.json"


def save_baseline(directory: str | Path, snapshot: dict[str, Any]) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = _path(directory, snapshot["host"])
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)
    return path


def load_baseline(directory: str | Path, host: str) -> dict[str, Any] | None:
    path = _path(Path(directory), host)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
