import json
from dataclasses import asdict
from pathlib import Path


def write_json(result, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(result), indent=2, default=str), encoding="utf-8")
