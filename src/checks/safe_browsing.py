from __future__ import annotations

import asyncio
from dataclasses import dataclass

import aiohttp

from . import url_utils

TIMEOUT_SECONDS = 8
RETRY_BACKOFF_SECONDS = 0.6
CACHE_TTL_SECONDS = 30 * 60
ERROR_CACHE_TTL_SECONDS = 3 * 60
MAX_URL_LENGTH = 2048
MAX_CACHE_ITEMS = 2000

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]

THREAT_LABELS = {
    "MALWARE": "вредоносное ПО",
    "SOCIAL_ENGINEERING": "возможный фишинг/обман",
    "UNWANTED_SOFTWARE": "нежелательное ПО",
    "POTENTIALLY_HARMFUL_APPLICATION": "потенциально вредное ПО",
}


@dataclass
class SafeBrowsingResult:
    status: str
    threats: list[str]
    detail: str


_cache: dict[str, tuple[float, float, SafeBrowsingResult]] = {}


def _endpoint(api_key: str) -> str:
    return f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"


def _normalize_url(raw: str) -> str:
    return url_utils.normalize_for_lookup(raw)


def _cache_get(key: str) -> SafeBrowsingResult | None:
    now = asyncio.get_running_loop().time()
    cached = _cache.get(key)
    if not cached:
        return None
    ts, ttl, result = cached
    if now - ts > ttl:
        _cache.pop(key, None)
        return None
    return result


def _cache_set(key: str, result: SafeBrowsingResult, ttl: float = CACHE_TTL_SECONDS) -> None:
    now = asyncio.get_running_loop().time()
    if key in _cache:
        _cache.pop(key, None)
    _cache[key] = (now, ttl, result)
    while len(_cache) > MAX_CACHE_ITEMS:
        oldest = next(iter(_cache))
        _cache.pop(oldest, None)


def _label_threats(threats: list[str]) -> str:
    return ", ".join(THREAT_LABELS.get(t, t) for t in threats)


async def _post_json(api_key: str, payload: dict) -> tuple[int, dict]:
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(_endpoint(api_key), json=payload) as resp:
            data = await resp.json(content_type=None)
            return resp.status, data


async def check_url(url: str, api_key: str | None) -> SafeBrowsingResult:
    if not api_key:
        return SafeBrowsingResult(
            status="not_configured",
            threats=[],
            detail="Google Safe Browsing: не настроено.",
        )

    try:
        normalized = _normalize_url(url)
    except Exception:
        return SafeBrowsingResult(
            status="error",
            threats=[],
            detail="Google Safe Browsing: некорректный URL.",
        )

    if len(normalized) > MAX_URL_LENGTH:
        return SafeBrowsingResult(
            status="error",
            threats=[],
            detail="Google Safe Browsing: URL слишком длинный для проверки.",
        )

    cached = _cache_get(normalized)
    if cached:
        return cached

    payload = {
        "client": {"clientId": "linkguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": normalized}],
        },
    }

    for attempt in range(2):
        try:
            status, data = await _post_json(api_key, payload)
        except asyncio.TimeoutError:
            if attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            result = SafeBrowsingResult(
                status="error",
                threats=[],
                detail="Google Safe Browsing: таймаут.",
            )
            _cache_set(normalized, result, ERROR_CACHE_TTL_SECONDS)
            return result
        except aiohttp.ClientError:
            if attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            result = SafeBrowsingResult(
                status="error",
                threats=[],
                detail="Google Safe Browsing: ошибка сети.",
            )
            _cache_set(normalized, result, ERROR_CACHE_TTL_SECONDS)
            return result

        if status in {429, 503} and attempt == 0:
            await asyncio.sleep(RETRY_BACKOFF_SECONDS)
            continue
        if status == 403:
            result = SafeBrowsingResult(
                status="error",
                threats=[],
                detail="Google Safe Browsing: доступ запрещен (403).",
            )
            _cache_set(normalized, result, ERROR_CACHE_TTL_SECONDS)
            return result
        if status != 200:
            result = SafeBrowsingResult(
                status="error",
                threats=[],
                detail=f"Google Safe Browsing: ошибка {status}.",
            )
            _cache_set(normalized, result, ERROR_CACHE_TTL_SECONDS)
            return result

        matches = data.get("matches", [])
        if not matches:
            result = SafeBrowsingResult(
                status="clean",
                threats=[],
                detail="Google Safe Browsing: угроз не найдено.",
            )
            _cache_set(normalized, result)
            return result

        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        label = _label_threats(threats)
        result = SafeBrowsingResult(
            status="hit",
            threats=threats,
            detail="Google Safe Browsing: обнаружены угрозы (" + label + ").",
        )
        _cache_set(normalized, result)
        return result

    result = SafeBrowsingResult(
        status="error",
        threats=[],
        detail="Google Safe Browsing: неизвестная ошибка.",
    )
    _cache_set(normalized, result, ERROR_CACHE_TTL_SECONDS)
    return result
