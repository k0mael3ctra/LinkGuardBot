from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import time

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "analytics.sqlite"


@dataclass
class Metrics:
    total_users: int
    total_events: int
    total_checks: int
    total_manual_checks: int
    total_auto_checks: int
    total_deepchecks: int
    total_errors: int
    dau: int
    wau: int
    mau: int
    generated_at: float


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
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
    conn.commit()


def log_event(user_id: int | None, event: str, chat_type: str | None) -> None:
    if not user_id or not event:
        return
    with _connect() as conn:
        _init_db(conn)
        conn.execute(
            "INSERT INTO events (ts, user_id, event, chat_type) VALUES (?, ?, ?, ?)",
            (time.time(), int(user_id), event, chat_type or "unknown"),
        )
        conn.commit()


def _count(conn: sqlite3.Connection, query: str, params: tuple = ()) -> int:
    cur = conn.execute(query, params)
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _since(days: int) -> float:
    return time.time() - (days * 86400)


def get_metrics() -> Metrics:
    with _connect() as conn:
        _init_db(conn)
        total_events = _count(conn, "SELECT COUNT(*) FROM events")
        total_users = _count(conn, "SELECT COUNT(DISTINCT user_id) FROM events")
        total_checks = _count(
            conn,
            "SELECT COUNT(*) FROM events WHERE event IN ('check', 'deepcheck', 'auto_check')",
        )
        total_manual_checks = _count(
            conn,
            "SELECT COUNT(*) FROM events WHERE event IN ('check', 'deepcheck')",
        )
        total_auto_checks = _count(conn, "SELECT COUNT(*) FROM events WHERE event = 'auto_check'")
        total_deepchecks = _count(conn, "SELECT COUNT(*) FROM events WHERE event = 'deepcheck'")
        total_errors = _count(conn, "SELECT COUNT(*) FROM events WHERE event LIKE '%_error'")
        dau = _count(conn, "SELECT COUNT(DISTINCT user_id) FROM events WHERE ts >= ?", (_since(1),))
        wau = _count(conn, "SELECT COUNT(DISTINCT user_id) FROM events WHERE ts >= ?", (_since(7),))
        mau = _count(conn, "SELECT COUNT(DISTINCT user_id) FROM events WHERE ts >= ?", (_since(30),))

    return Metrics(
        total_users=total_users,
        total_events=total_events,
        total_checks=total_checks,
        total_manual_checks=total_manual_checks,
        total_auto_checks=total_auto_checks,
        total_deepchecks=total_deepchecks,
        total_errors=total_errors,
        dau=dau,
        wau=wau,
        mau=mau,
        generated_at=time.time(),
    )


def format_metrics(metrics: Metrics) -> str:
    lines = [
        "Статистика бота",
        f"Пользователи всего: {metrics.total_users}",
        f"DAU/WAU/MAU: {metrics.dau}/{metrics.wau}/{metrics.mau}",
        f"Проверки всего: {metrics.total_checks}",
        f"Проверки вручную: {metrics.total_manual_checks}",
        f"Авто-проверки: {metrics.total_auto_checks}",
        f"Deepcheck: {metrics.total_deepchecks}",
        f"Ошибки проверок: {metrics.total_errors}",
    ]
    return "\n".join(lines)


def write_metrics_csv(metrics: Metrics) -> Path:
    path = DB_PATH.parent / "metrics.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_users", metrics.total_users])
        writer.writerow(["total_events", metrics.total_events])
        writer.writerow(["total_checks", metrics.total_checks])
        writer.writerow(["total_manual_checks", metrics.total_manual_checks])
        writer.writerow(["total_auto_checks", metrics.total_auto_checks])
        writer.writerow(["total_deepchecks", metrics.total_deepchecks])
        writer.writerow(["total_errors", metrics.total_errors])
        writer.writerow(["dau", metrics.dau])
        writer.writerow(["wau", metrics.wau])
        writer.writerow(["mau", metrics.mau])
        writer.writerow(["generated_at", int(metrics.generated_at)])
    return path
