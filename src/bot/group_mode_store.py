from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

_lock = asyncio.Lock()


def _path() -> Path:
    root = Path(__file__).resolve().parents[2]
    path = root / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path / "group_modes.json"


def _load() -> dict[str, Any]:
    path = _path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict[str, Any]) -> None:
    _path().write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


async def get_mode(chat_id: int) -> str | None:
    async with _lock:
        data = _load()
        return data.get(str(chat_id))


async def set_mode(chat_id: int, mode: str) -> None:
    async with _lock:
        data = _load()
        data[str(chat_id)] = mode
        _save(data)
