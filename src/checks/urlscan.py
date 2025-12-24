from __future__ import annotations

import asyncio
from dataclasses import dataclass

import aiohttp

TIMEOUT_SECONDS = 8
RETRY_BACKOFF_SECONDS = 0.6


@dataclass
class UrlscanResult:
    status: str
    detail: str
    result_url: str | None


def _endpoint() -> str:
    return "https://urlscan.io/api/v1/scan/"


def _result_endpoint(uuid: str) -> str:
    return f"https://urlscan.io/api/v1/result/{uuid}/"


async def scan_url(url: str, api_key: str | None) -> UrlscanResult:
    if not api_key:
        return UrlscanResult(
            status="not_configured",
            detail="urlscan.io: не настроено.",
            result_url=None,
        )

    payload = {"url": url, "visibility": "private"}
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)

    for attempt in range(2):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(_endpoint(), json=payload, headers={"API-Key": api_key}) as resp:
                    if resp.status in {429, 503} and attempt == 0:
                        await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                        continue
                    if resp.status != 200:
                        return UrlscanResult(
                            status="error",
                            detail=f"urlscan.io: ошибка {resp.status}.",
                            result_url=None,
                        )
                    data = await resp.json()
                    uuid = data.get("uuid")
                    result_url = data.get("result")
                    if not uuid:
                        return UrlscanResult(
                            status="error",
                            detail="urlscan.io: неверный ответ.",
                            result_url=None,
                        )

                    await asyncio.sleep(1.0)
                    async with session.get(_result_endpoint(uuid)) as result_resp:
                        if result_resp.status == 200:
                            return UrlscanResult(
                                status="ready",
                                detail="urlscan.io: отчет готов.",
                                result_url=result_url or _result_endpoint(uuid),
                            )
                        return UrlscanResult(
                            status="queued",
                            detail="urlscan.io: отчет в очереди.",
                            result_url=result_url or _result_endpoint(uuid),
                        )
        except asyncio.TimeoutError:
            if attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            return UrlscanResult(status="error", detail="urlscan.io: таймаут.", result_url=None)
        except aiohttp.ClientError:
            if attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            return UrlscanResult(status="error", detail="urlscan.io: ошибка сети.", result_url=None)

    return UrlscanResult(status="error", detail="urlscan.io: неизвестная ошибка.", result_url=None)
