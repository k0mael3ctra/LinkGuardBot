from src.checks.http_fetch import is_forbidden_ip


def test_private_ipv4_blocked() -> None:
    assert is_forbidden_ip("127.0.0.1")
    assert is_forbidden_ip("10.0.0.5")
    assert is_forbidden_ip("192.168.1.10")


def test_public_ipv4_allowed() -> None:
    assert not is_forbidden_ip("8.8.8.8")


def test_private_ipv6_blocked() -> None:
    assert is_forbidden_ip("::1")
