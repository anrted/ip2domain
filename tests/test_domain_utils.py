from ip2domain.core.domain_utils import normalize_domain


def test_normalize_domain_rejects_noise_and_ips():
    assert normalize_domain("*.Example.COM.") == "example.com"
    assert normalize_domain("https://example.com") is None
    assert normalize_domain("1.2.3.4") is None
    assert normalize_domain("bad host.example") is None


def test_normalize_domain_supports_idn():
    assert normalize_domain("пример.рф") == "xn--e1afmkfd.xn--p1ai"


def test_syntax_alone_cannot_distinguish_html_noise_from_dns():
    assert normalize_domain("favicon.ico") == "favicon.ico"
    assert normalize_domain("document.scripts.length") == "document.scripts.length"
