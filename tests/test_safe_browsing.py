from __future__ import annotations

import asyncio

from src.checks import http_fetch
from src.checks import safe_browsing
from src.checks import threat_feeds
from src.risk_engine import analyze_url


def test_safe_browsing_not_configured() -> None:
    result = asyncio.run(safe_browsing.check_url("example.com", None))
    assert result.status == "not_configured"


def test_gsb_hit_sets_high(monkeypatch) -> None:
    async def fake_check_url(url: str, api_key: str | None) -> safe_browsing.SafeBrowsingResult:
        return safe_browsing.SafeBrowsingResult(
            status="hit",
            threats=["MALWARE"],
            detail="Google Safe Browsing: threats found (вредоносное ПО).",
        )

    async def fake_feed(url: str, host: str):
        return []

    async def fake_fetch(url: str):
        return http_fetch.FetchResult(
            final_url=url,
            status=200,
            headers={},
            body_text=None,
            content_type=None,
            redirect_chain=[],
            blocked_reason=None,
            error=None,
        )

    monkeypatch.setattr(safe_browsing, "check_url", fake_check_url)
    monkeypatch.setattr(threat_feeds, "check_url", fake_feed)
    monkeypatch.setattr(http_fetch, "safe_fetch", fake_fetch)

    report = asyncio.run(analyze_url("https://example.com", None, "fake", None))
    assert report.risk_level == "HIGH"
    assert "Google Safe Browsing: обнаружены угрозы." in report.reasons

