from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass
class ContentFinding:
    reason: str
    technical: str
    score: int


FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
PASSWORD_RE = re.compile(r"type=\"?password\"?", re.IGNORECASE)
EMAIL_RE = re.compile(r"type=\"?email\"?", re.IGNORECASE)
ACTION_RE = re.compile(r"action=\"([^\"]+)\"", re.IGNORECASE)
METHOD_RE = re.compile(r"method=\"([^\"]+)\"", re.IGNORECASE)
IFRAME_RE = re.compile(r"<iframe\b", re.IGNORECASE)
META_REFRESH_RE = re.compile(r"http-equiv=\"?refresh\"?", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=\"([^\"]+)\"", re.IGNORECASE)
SUSPICIOUS_WORDS = [
    "login",
    "password",
    "verify",
    "account",
    "signin",
    "bank",
    "update",
    "security",
    "confirm",
]
DANGEROUS_WORDS = ["download", "installer", "setup", "update now", "browser update"]


def _host_from_url(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def analyze_html(html: str, base_host: str) -> list[ContentFinding]:
    findings: list[ContentFinding] = []
    lowered = html.lower()

    has_form = bool(FORM_RE.search(lowered))
    has_password = bool(PASSWORD_RE.search(lowered))
    has_email = bool(EMAIL_RE.search(lowered))

    if has_form and has_password:
        findings.append(
            ContentFinding(
                reason="Обнаружена форма ввода пароля.",
                technical="Контент: форма с полем password",
                score=25,
            )
        )
    elif has_form and has_email:
        findings.append(
            ContentFinding(
                reason="Обнаружена форма с email-полем.",
                technical="Контент: форма с полем email",
                score=12,
            )
        )
    elif has_form:
        findings.append(
            ContentFinding(
                reason="На странице есть форма ввода данных.",
                technical="Контент: форма ввода",
                score=10,
            )
        )

    action_match = ACTION_RE.search(lowered)
    if action_match:
        action_url = action_match.group(1)
        action_host = _host_from_url(action_url)
        if action_host and action_host != base_host.lower():
            findings.append(
                ContentFinding(
                    reason="Форма отправляет данные на другой домен.",
                    technical=f"Контент: form action -> {action_host}",
                    score=15,
                )
            )
        if action_url.lower().startswith("mailto:"):
            findings.append(
                ContentFinding(
                    reason="Форма отправляет данные на email.",
                    technical="Контент: form action -> mailto",
                    score=15,
                )
            )
        if action_url.lower().startswith("http://"):
            findings.append(
                ContentFinding(
                    reason="Форма отправляет данные по незащищенному HTTP.",
                    technical="Контент: form action -> http",
                    score=10,
                )
            )

    method_match = METHOD_RE.search(lowered)
    if method_match and method_match.group(1).lower() == "post" and has_form:
        findings.append(
            ContentFinding(
                reason="Форма отправляет данные методом POST.",
                technical="Контент: form method=post",
                score=5,
            )
        )

    if IFRAME_RE.search(lowered):
        findings.append(
            ContentFinding(
                reason="На странице используются iframe.",
                technical="Контент: iframe",
                score=6,
            )
        )

    if META_REFRESH_RE.search(lowered):
        findings.append(
            ContentFinding(
                reason="Есть auto-redirect через meta refresh.",
                technical="Контент: meta refresh",
                score=8,
            )
        )

    script_hosts = []
    for match in SCRIPT_SRC_RE.findall(lowered):
        host = _host_from_url(match)
        if host:
            script_hosts.append(host)
    external_scripts = {h for h in script_hosts if h != base_host.lower()}
    if len(external_scripts) >= 3:
        findings.append(
            ContentFinding(
                reason="Подключено много внешних скриптов.",
                technical="Контент: внешние скрипты: " + ", ".join(sorted(external_scripts)[:5]),
                score=8,
            )
        )

    hit_words = [w for w in SUSPICIOUS_WORDS if w in lowered]
    if hit_words:
        findings.append(
            ContentFinding(
                reason="Есть слова, характерные для фишинга или логина.",
                technical="Контент: ключевые слова: " + ", ".join(hit_words),
                score=5,
            )
        )

    danger_hits = [w for w in DANGEROUS_WORDS if w in lowered]
    if danger_hits:
        findings.append(
            ContentFinding(
                reason="Есть признаки навязывания загрузки или обновления.",
                technical="Контент: слова: " + ", ".join(danger_hits),
                score=8,
            )
        )

    return findings
