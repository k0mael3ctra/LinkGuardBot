from __future__ import annotations

import asyncio
import time

from . import db

_lock = asyncio.Lock()


def _get_mode_sync(chat_id: int) -> str | None:
    with db.connect() as conn:
        db.ensure_db(conn)
        cur = conn.execute("SELECT mode FROM group_modes WHERE chat_id = ?", (int(chat_id),))
        row = cur.fetchone()
        return str(row[0]) if row and row[0] else None


def _set_mode_sync(chat_id: int, mode: str) -> None:
    mode = mode.strip().lower()
    with db.connect() as conn:
        db.ensure_db(conn)
        conn.execute(
            """
            INSERT INTO group_modes (chat_id, mode, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                mode = excluded.mode,
                updated_at = excluded.updated_at
            """,
            (int(chat_id), mode, time.time()),
        )
        conn.commit()


async def get_mode(chat_id: int) -> str | None:
    async with _lock:
        return await asyncio.to_thread(_get_mode_sync, chat_id)


async def set_mode(chat_id: int, mode: str) -> None:
    async with _lock:
        await asyncio.to_thread(_set_mode_sync, chat_id, mode)
