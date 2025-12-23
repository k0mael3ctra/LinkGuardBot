from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from urllib.parse import parse_qs, urlsplit, urlunsplit


@dataclass(frozen=True)
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    host: str
    path: str
    query: str
    display_host: str


SUSPICIOUS_PARAMS = {"redirect", "url", "next", "continue", "return"}
SHORTENERS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "bitly.com",
    "rebrand.ly",
    "tiny.cc",
    "t.ly",
    "lc.chat",
}


def decode_idn(host: str) -> str:
    if not host:
        return host
    try:
        if "xn--" in host:
            return host.encode("ascii").decode("idna")
        return host
    except Exception:
        return host


def to_punycode(host: str) -> str:
    if not host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def normalize_url(raw: str) -> NormalizedURL:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    query = parts.query or ""
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    normalized = urlunsplit((scheme, netloc, path, query, ""))
    return NormalizedURL(
        original=raw,
        normalized=normalized,
        scheme=scheme,
        host=host,
        path=path,
        query=query,
        display_host=decode_idn(host),
    )


def normalize_for_lookup(raw: str) -> str:
    raw = "".join(ch for ch in raw.strip() if not ch.isspace())
    if not raw:
        raise ValueError("Empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = to_punycode((parts.hostname or "").lower())
    path = parts.path or "/"
    query = parts.query or ""
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((scheme, netloc, path, query, ""))


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_shortener(host: str) -> bool:
    return host in SHORTENERS


def suspicious_params(query: str) -> list[str]:
    params = parse_qs(query)
    hits = []
    for key in params.keys():
        if key.lower() in SUSPICIOUS_PARAMS:
            hits.append(key)
    return hits


def evaluate_risk(normalized: NormalizedURL) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if "@" in normalized.original:
        score += 15
        reasons.append("Символ @ в ссылке может скрывать реальный адрес.")

    if is_ip_address(normalized.host):
        score += 20
        reasons.append("Вместо домена используется IP-адрес.")

    if is_shortener(normalized.host):
        score += 10
        reasons.append("Используется сервис сокращения ссылок.")

    suspicious = suspicious_params(normalized.query)
    if suspicious:
        score += 15
        reasons.append("Подозрительные параметры: " + ", ".join(sorted(set(suspicious))))

    labels = [p for p in normalized.host.split(".") if p]
    if len(labels) > 4:
        score += 10
        reasons.append("Слишком много поддоменов.")

    if len(normalized.host) > 50:
        score += 10
        reasons.append("Домен слишком длинный.")

    hyphens = normalized.host.count("-")
    digits = sum(1 for ch in normalized.host if ch.isdigit())
    if hyphens >= 4:
        score += 10
        reasons.append("В домене много дефисов.")

    if digits >= 5:
        score += 10
        reasons.append("В домене много цифр.")

    if normalized.scheme != "https":
        score += 5
        reasons.append("Ссылка не использует HTTPS.")

    return score, reasons
