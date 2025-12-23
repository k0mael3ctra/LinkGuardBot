from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class HistoryItem:
    url: str
    risk_level: str
    risk_score: int
    timestamp: float


MAX_ITEMS_PER_USER = 20

_lock = asyncio.Lock()


def _history_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    path = root / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path / "history.json"


def _load_raw() -> dict[str, list[dict[str, Any]]]:
    path = _history_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_raw(data: dict[str, list[dict[str, Any]]]) -> None:
    _history_path().write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


async def add_item(user_id: int, item: HistoryItem) -> None:
    async with _lock:
        data = _load_raw()
        key = str(user_id)
        items = data.get(key, [])
        items.insert(0, {
            "url": item.url,
            "risk_level": item.risk_level,
            "risk_score": item.risk_score,
            "timestamp": item.timestamp,
        })
        data[key] = items[:MAX_ITEMS_PER_USER]
        _save_raw(data)


async def get_items(user_id: int, limit: int = 5) -> list[HistoryItem]:
    async with _lock:
        data = _load_raw()
        key = str(user_id)
        items = data.get(key, [])[:limit]
        return [
            HistoryItem(
                url=item.get("url", ""),
                risk_level=item.get("risk_level", ""),
                risk_score=int(item.get("risk_score", 0)),
                timestamp=float(item.get("timestamp", 0)),
            )
            for item in items
        ]
