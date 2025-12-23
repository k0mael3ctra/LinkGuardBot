from src.checks.url_utils import normalize_url, suspicious_params


def test_normalize_adds_scheme() -> None:
    result = normalize_url("example.com")
    assert result.normalized.startswith("https://")


def test_suspicious_params_detected() -> None:
    hits = suspicious_params("next=https://evil.com&ok=1")
    assert "next" in hits


def test_punycode_display() -> None:
    result = normalize_url("http://xn--e1afmkfd.xn--p1ai")
    assert result.display_host != result.host
