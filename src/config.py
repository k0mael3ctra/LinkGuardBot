from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    bot_token: str
    vt_api_key: str | None
    google_safe_browsing_api_key: str | None
    urlscan_api_key: str | None
    group_mode: str
    admin_ids: set[int]


def _load_env() -> None:
    root = Path(__file__).resolve().parents[1]
    load_dotenv(root / ".env")


def _parse_admin_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if value.isdigit():
            ids.add(int(value))
    return ids


def get_settings() -> Settings:
    _load_env()
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("BOT_TOKEN is missing. Create .env and set BOT_TOKEN.")
    vt_key = os.getenv("VT_API_KEY", "").strip() or None
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip() or None
    urlscan_key = os.getenv("URLSCAN_API_KEY", "").strip() or None
    group_mode = os.getenv("GROUP_MODE", "quiet").strip().lower()
    if group_mode not in {"quiet", "active"}:
        group_mode = "quiet"
    admin_ids = _parse_admin_ids(os.getenv("ADMIN_IDS", ""))
    return Settings(
        bot_token=token,
        vt_api_key=vt_key,
        google_safe_browsing_api_key=gsb_key,
        urlscan_api_key=urlscan_key,
        group_mode=group_mode,
        admin_ids=admin_ids,
    )
