from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .checks import content_scan
from .checks import headers as headers_mod
from .checks import http_fetch
from .checks import reputation
from .checks import safe_browsing
from .checks import threat_feeds
from .checks import urlscan
from .checks import url_utils


@dataclass
class Report:
    normalized_url: str
    scheme: str
    host: str
    path: str
    query: str
    display_host: str
    risk_score: int
    risk_level: str
    reasons: list[str]
    technical: list[str]
    intel: list[str]
    unavailable: list[str]


def _risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _redirect_summary(chain: list[str], final_url: str) -> tuple[int, str | None]:
    if not chain:
        return 0, None
    hosts = [urlsplit(url).hostname for url in chain]
    final_host = urlsplit(final_url).hostname
    host_changes = len({h for h in hosts + [final_host] if h})
    if host_changes > 1:
        return 10, "Редиректы на разные домены."
    if len(chain) >= 2:
        return 5, "Несколько редиректов подряд."
    return 0, None


async def _with_timeout(coro: Any, label: str, timeout: float) -> tuple[str, Any]:
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        return "ok", result
    except asyncio.TimeoutError:
        return "timeout", f"{label}: таймаут."
    except Exception:
        return "error", f"{label}: ошибка."


async def analyze_url(
    raw_url: str,
    vt_api_key: str | None,
    gsb_api_key: str | None,
    urlscan_api_key: str | None,
    deepcheck: bool = False,
) -> Report:
    normalized = url_utils.normalize_url(raw_url)

    score, reasons = url_utils.evaluate_risk(normalized)
    technical: list[str] = []
    intel: list[str] = []
    unavailable: list[str] = []

    timeout = 12.0
    tasks = {
        "feeds": _with_timeout(threat_feeds.check_url(normalized.normalized, normalized.host), "Публичные базы", timeout),
        "gsb": _with_timeout(safe_browsing.check_url(normalized.normalized, gsb_api_key), "Google Safe Browsing", timeout),
        "fetch": _with_timeout(http_fetch.safe_fetch(normalized.normalized), "HTTP запрос", timeout),
        "vt": _with_timeout(reputation.check_reputation(normalized.normalized, vt_api_key), "VirusTotal", timeout),
    }
    keys = list(tasks.keys())
    results = await asyncio.gather(*tasks.values())
    result_map = dict(zip(keys, results))

    feeds_state, feeds_result = result_map["feeds"]
    if feeds_state == "ok":
        feed_hits = feeds_result
        if feed_hits:
            score += 60
            for hit in feed_hits:
                intel.append(f"{hit.source}: {hit.detail}")
            reasons.append("Совпадение в публичных базах угроз.")
        else:
            intel.append("Публичные базы: совпадений нет.")
    else:
        unavailable.append(feeds_result)

    gsb_state, gsb_result = result_map["gsb"]
    if gsb_state == "ok":
        intel.append(gsb_result.detail)
        if gsb_result.status == "hit":
            score = max(score, 80)
            reasons.append("Google Safe Browsing: обнаружены угрозы.")
        elif gsb_result.status == "error":
            unavailable.append(gsb_result.detail)
    else:
        unavailable.append(gsb_result)

    vt_state, vt_result = result_map["vt"]
    if vt_state == "ok":
        intel.append(vt_result.detail)
        if vt_result.status == "hit":
            score = max(score, 70)
            reasons.append("VirusTotal: обнаружены срабатывания.")
        elif vt_result.status == "error":
            unavailable.append(vt_result.detail)
    else:
        unavailable.append(vt_result)

    fetch_state, fetch_result = result_map["fetch"]
    if fetch_state == "ok":
        if fetch_result.blocked_reason:
            score += 25
            reasons.append(fetch_result.blocked_reason)
            technical.append(f"Запрос заблокирован: {fetch_result.blocked_reason}")
        elif fetch_result.error:
            score += 5
            reasons.append("Не удалось безопасно получить ответ сайта.")
            unavailable.append(fetch_result.error)
        else:
            technical.append(f"HTTP статус: {fetch_result.status}")
            technical.append(f"Финальный URL: {fetch_result.final_url}")
            if fetch_result.content_type:
                technical.append(f"Content-Type: {fetch_result.content_type}")
            missing = headers_mod.missing_security_headers(fetch_result.headers)
            if missing:
                score += min(25, 5 * len(missing))
                reasons.append("Нет защитных заголовков: " + ", ".join(missing))
                technical.append("Защитные заголовки: отсутствуют " + ", ".join(missing))
            else:
                technical.append("Защитные заголовки: все основные присутствуют")

            if fetch_result.redirect_chain:
                technical.append("Редиректы: " + " -> ".join(fetch_result.redirect_chain + [fetch_result.final_url]))
                redirect_score, redirect_reason = _redirect_summary(fetch_result.redirect_chain, fetch_result.final_url)
                if redirect_reason:
                    score += redirect_score
                    reasons.append(redirect_reason)

            if fetch_result.body_text:
                findings = content_scan.analyze_html(fetch_result.body_text, normalized.host)
                for finding in findings:
                    score += finding.score
                    reasons.append(finding.reason)
                    technical.append(finding.technical)
    else:
        unavailable.append(fetch_result)

    if deepcheck or score >= 70:
        scan_state, scan_result = await _with_timeout(
            urlscan.scan_url(normalized.normalized, urlscan_api_key),
            "urlscan.io",
            timeout,
        )
        if scan_state == "ok":
            if scan_result.result_url:
                intel.append(f"{scan_result.detail} {scan_result.result_url}")
            else:
                intel.append(scan_result.detail)
            if scan_result.status == "error":
                unavailable.append(scan_result.detail)
        else:
            unavailable.append(scan_result)
    else:
        intel.append("urlscan.io: пропущено (запусти /deepcheck для полного скана).")

    score = max(0, min(100, score))
    level = _risk_level(score)

    if not reasons:
        reasons.append("Явных признаков риска не найдено.")

    return Report(
        normalized_url=normalized.normalized,
        scheme=normalized.scheme,
        host=normalized.host,
        path=normalized.path,
        query=normalized.query,
        display_host=normalized.display_host,
        risk_score=score,
        risk_level=level,
        reasons=reasons,
        technical=technical,
        intel=intel,
        unavailable=unavailable,
    )



