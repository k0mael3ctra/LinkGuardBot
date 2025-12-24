from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "linkguard.sqlite"

_initialized = False


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            user_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            chat_type TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event ON events(event)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_history_user_ts ON history(user_id, ts)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS group_modes (
            chat_id INTEGER PRIMARY KEY,
            mode TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )

    conn.commit()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _rename_backup(path: Path) -> None:
    target = Path(str(path) + ".bak")
    if target.exists():
        target = Path(str(path) + f".{int(time.time())}.bak")
    try:
        path.rename(target)
    except Exception:
        pass


def _migrate_history(conn: sqlite3.Connection) -> None:
    path = DB_PATH.parent / "history.json"
    if not path.exists():
        return

    cur = conn.execute("SELECT COUNT(*) FROM history")
    if int(cur.fetchone()[0]) > 0:
        return

    raw = _read_json(path)
    if not isinstance(raw, dict):
        return

    rows: list[tuple[float, int, str, str, int]] = []
    for user_id_str, items in raw.items():
        if not isinstance(items, list):
            continue
        if not str(user_id_str).isdigit():
            continue
        user_id = int(user_id_str)
        for item in items:
            if not isinstance(item, dict):
                continue
            ts = float(item.get("timestamp", 0) or 0)
            url = str(item.get("url", "") or "")
            risk_level = str(item.get("risk_level", "") or "")
            risk_score = int(item.get("risk_score", 0) or 0)
            if not url:
                continue
            rows.append((ts, user_id, url, risk_level, risk_score))

    if not rows:
        return

    conn.executemany(
        "INSERT INTO history (ts, user_id, url, risk_level, risk_score) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    _rename_backup(path)


def _migrate_group_modes(conn: sqlite3.Connection) -> None:
    path = DB_PATH.parent / "group_modes.json"
    if not path.exists():
        return

    cur = conn.execute("SELECT COUNT(*) FROM group_modes")
    if int(cur.fetchone()[0]) > 0:
        return

    raw = _read_json(path)
    if not isinstance(raw, dict):
        return

    now = time.time()
    rows: list[tuple[int, str, float]] = []
    for chat_id_str, mode in raw.items():
        if not str(chat_id_str).lstrip("-").isdigit():
            continue
        chat_id = int(chat_id_str)
        mode_str = str(mode).strip().lower()
        if mode_str not in {"quiet", "active"}:
            continue
        rows.append((chat_id, mode_str, now))

    if not rows:
        return

    conn.executemany(
        "INSERT INTO group_modes (chat_id, mode, updated_at) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()
    _rename_backup(path)


def ensure_db(conn: sqlite3.Connection) -> None:
    global _initialized
    if _initialized:
        return
    _init_schema(conn)
    _migrate_history(conn)
    _migrate_group_modes(conn)
    _initialized = True
