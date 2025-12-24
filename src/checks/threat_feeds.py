from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import aiohttp

from . import url_utils


LOGGER = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 6 * 60 * 60
TIMEOUT_SECONDS = 8


@dataclass
class FeedFinding:
    source: str
    match_type: str
    detail: str


@dataclass
class FeedData:
    name: str
    urls: set[str]
    domains: set[str]
    loaded_at: float
    stale: bool


@dataclass(frozen=True)
class FeedConfig:
    name: str
    url: str


FEEDS = [
    FeedConfig(name="URLhaus", url="https://urlhaus.abuse.ch/downloads/text/"),
]


_cache: dict[str, FeedData] = {}


def _cache_dir() -> Path:
    root = Path(__file__).resolve().parents[2]
    path = root / "data" / "feeds"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _meta_path() -> Path:
    return _cache_dir() / "meta.json"


def _load_meta() -> dict[str, float]:
    path = _meta_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_meta(meta: dict[str, float]) -> None:
    _meta_path().write_text(json.dumps(meta), encoding="utf-8")


def _feed_path(name: str) -> Path:
    safe = name.lower().replace(" ", "_")
    return _cache_dir() / f"{safe}.txt"


def _parse_lines(lines: Iterable[str]) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()

    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if not value.startswith("http"):
            value = "http://" + value
        try:
            parts = urlsplit(value)
        except Exception:
            continue
        if not parts.hostname:
            continue
        host = parts.hostname.lower()
        domains.add(host)
        normalized = url_utils.normalize_url(value).normalized.lower().rstrip("/")
        urls.add(normalized)

    return urls, domains


async def _fetch_text(url: str) -> str:
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text()


async def _load_feed(config: FeedConfig) -> FeedData:
    now = asyncio.get_running_loop().time()
    if config.name in _cache:
        cached = _cache[config.name]
        if now - cached.loaded_at < CACHE_TTL_SECONDS:
            return cached

    meta = _load_meta()
    path = _feed_path(config.name)
    cached_at = meta.get(config.name)
    stale = False

    if cached_at and path.exists() and now - cached_at < CACHE_TTL_SECONDS:
        text = path.read_text(encoding="utf-8", errors="ignore")
        urls, domains = _parse_lines(text.splitlines())
        data = FeedData(config.name, urls, domains, cached_at, stale)
        _cache[config.name] = data
        return data

    try:
        text = await _fetch_text(config.url)
        path.write_text(text, encoding="utf-8")
        meta[config.name] = now
        _save_meta(meta)
        urls, domains = _parse_lines(text.splitlines())
        data = FeedData(config.name, urls, domains, now, stale)
        _cache[config.name] = data
        return data
    except Exception as exc:
        LOGGER.warning("Threat feed fetch failed: %s (%s)", config.name, exc)
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="ignore")
            urls, domains = _parse_lines(text.splitlines())
            data = FeedData(config.name, urls, domains, cached_at or now, True)
            _cache[config.name] = data
            return data
        return FeedData(config.name, set(), set(), now, True)


async def check_url(url: str, host: str) -> list[FeedFinding]:
    findings: list[FeedFinding] = []
    normalized = url.lower().rstrip("/")
    host = host.lower()

    for config in FEEDS:
        data = await _load_feed(config)
        if normalized in data.urls:
            detail = "совпадение URL"
            if data.stale:
                detail += " (кеш устарел)"
            findings.append(FeedFinding(source=config.name, match_type="url", detail=detail))
            continue
        if host in data.domains:
            detail = "совпадение домена"
            if data.stale:
                detail += " (кеш устарел)"
            findings.append(FeedFinding(source=config.name, match_type="domain", detail=detail))

    return findings
