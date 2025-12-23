from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass

import aiohttp

TIMEOUT_SECONDS = 8


@dataclass
class ReputationResult:
    status: str
    detail: str
    malicious: int = 0
    suspicious: int = 0
    total: int = 0


def _format_detail(malicious: int, suspicious: int, total: int, categories: list[str], tags: list[str]) -> str:
    detected = malicious + suspicious
    ratio = f"{detected}/{total}" if total else "0/0"
    parts = [f"VirusTotal: detections {ratio} (malicious={malicious}, suspicious={suspicious})."]
    if categories:
        parts.append("Categories: " + ", ".join(categories[:3]) + ".")
    if tags:
        parts.append("Tags: " + ", ".join(tags[:4]) + ".")
    return " ".join(parts)


async def check_reputation(url: str, api_key: str | None) -> ReputationResult:
    if not api_key:
        return ReputationResult(status="not_configured", detail="VirusTotal: not configured (optional).")

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(endpoint, headers=headers) as resp:
                if resp.status == 404:
                    return ReputationResult(
                        status="clean",
                        detail="VirusTotal: not found (maybe needs analysis).",
                    )
                if resp.status == 429:
                    return ReputationResult(status="error", detail="VirusTotal: rate limit, try later.")
                if resp.status != 200:
                    return ReputationResult(status="error", detail=f"VirusTotal: error {resp.status}.")

                data = await resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                timeout_count = int(stats.get("timeout", 0))
                total = malicious + suspicious + harmless + undetected + timeout_count
                categories = sorted({v for v in (attrs.get("categories") or {}).values() if isinstance(v, str)})
                tags = [t for t in attrs.get("tags", []) if isinstance(t, str)]

                detail = _format_detail(malicious, suspicious, total, categories, tags)
                status = "hit" if (malicious + suspicious) > 0 else "clean"
                return ReputationResult(
                    status=status,
                    detail=detail,
                    malicious=malicious,
                    suspicious=suspicious,
                    total=total,
                )
    except asyncio.TimeoutError:
        return ReputationResult(status="error", detail="VirusTotal: timeout.")
    except aiohttp.ClientError:
        return ReputationResult(status="error", detail="VirusTotal: network error.")
