from __future__ import annotations

from typing import Mapping

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def missing_security_headers(headers: Mapping[str, str]) -> list[str]:
    present = {key.lower() for key in headers.keys()}
    return [h for h in REQUIRED_HEADERS if h.lower() not in present]
