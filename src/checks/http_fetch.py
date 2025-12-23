from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import aiohttp

USER_AGENT = "LinkGuardBot/1.0 (educational; safe)"
MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 8
MAX_BODY_BYTES = 200_000

FORBIDDEN_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class FetchResult:
    final_url: str
    status: int | None
    headers: Mapping[str, str]
    body_text: str | None
    content_type: str | None
    redirect_chain: list[str]
    blocked_reason: str | None
    error: str | None


def is_forbidden_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in FORBIDDEN_NETS)


async def _resolve_host(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


async def _host_is_allowed(host: str) -> tuple[bool, str | None]:
    if not host:
        return False, "URL без домена."
    ips = await _resolve_host(host)
    if not ips:
        return False, "DNS не отвечает или домен не существует."
    for ip in ips:
        if is_forbidden_ip(ip):
            return False, f"Домен резолвится в приватный адрес {ip}."
    return True, None


async def _read_body(resp: aiohttp.ClientResponse) -> str | None:
    content_type = resp.headers.get("Content-Type", "")
    if not content_type.lower().startswith("text/html"):
        return None

    length = resp.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return None

    data = await resp.content.read(MAX_BODY_BYTES + 1)
    if len(data) > MAX_BODY_BYTES:
        return None

    return data.decode("utf-8", errors="ignore")


async def safe_fetch(url: str) -> FetchResult:
    current = url
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    chain: list[str] = []

    async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": USER_AGENT}) as session:
        for step in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in {"http", "https"}:
                return FetchResult(current, None, {}, None, None, chain, "Разрешены только http/https ссылки.", None)

            allowed, reason = await _host_is_allowed(parts.hostname or "")
            if not allowed:
                return FetchResult(current, None, {}, None, None, chain, reason, None)

            try:
                async with session.get(current, allow_redirects=False) as resp:
                    status = resp.status
                    headers = dict(resp.headers)
                    if status in {301, 302, 303, 307, 308}:
                        location = resp.headers.get("Location")
                        if not location:
                            return FetchResult(current, status, headers, None, None, chain, None, None)
                        chain.append(current)
                        if step >= MAX_REDIRECTS:
                            return FetchResult(current, status, headers, None, None, chain, None, "Слишком много редиректов.")
                        current = urljoin(current, location)
                        continue

                    body_text = await _read_body(resp)
                    content_type = resp.headers.get("Content-Type")
                    return FetchResult(str(resp.url), status, headers, body_text, content_type, chain, None, None)
            except asyncio.TimeoutError:
                return FetchResult(current, None, {}, None, None, chain, None, "Таймаут запроса.")
            except aiohttp.ClientError as exc:
                return FetchResult(current, None, {}, None, None, chain, None, f"Ошибка запроса: {exc}")

    return FetchResult(current, None, {}, None, None, chain, None, "Неизвестная ошибка.")
