from __future__ import annotations

import asyncio
from dataclasses import dataclass

from . import db


@dataclass
class HistoryItem:
    url: str
    risk_level: str
    risk_score: int
    timestamp: float


MAX_ITEMS_PER_USER = 20

_lock = asyncio.Lock()


def _add_item_sync(user_id: int, item: HistoryItem) -> None:
    with db.connect() as conn:
        db.ensure_db(conn)
        conn.execute(
            "INSERT INTO history (ts, user_id, url, risk_level, risk_score) VALUES (?, ?, ?, ?, ?)",
            (float(item.timestamp), int(user_id), item.url, item.risk_level, int(item.risk_score)),
        )
        conn.execute(
            """
            DELETE FROM history
            WHERE id IN (
                SELECT id FROM history
                WHERE user_id = ?
                ORDER BY ts DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (int(user_id), MAX_ITEMS_PER_USER),
        )
        conn.commit()


def _get_items_sync(user_id: int, limit: int) -> list[HistoryItem]:
    with db.connect() as conn:
        db.ensure_db(conn)
        cur = conn.execute(
            "SELECT url, risk_level, risk_score, ts FROM history WHERE user_id = ? ORDER BY ts DESC LIMIT ?",
            (int(user_id), int(limit)),
        )
        rows = cur.fetchall() or []
        return [
            HistoryItem(
                url=str(row[0] or ""),
                risk_level=str(row[1] or ""),
                risk_score=int(row[2] or 0),
                timestamp=float(row[3] or 0),
            )
            for row in rows
        ]


async def add_item(user_id: int, item: HistoryItem) -> None:
    async with _lock:
        await asyncio.to_thread(_add_item_sync, user_id, item)


async def get_items(user_id: int, limit: int = 5) -> list[HistoryItem]:
    async with _lock:
        return await asyncio.to_thread(_get_items_sync, user_id, limit)
