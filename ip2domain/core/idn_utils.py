"""
Utility functions for IDN (Internationalized Domain Names) and Punycode (xn--...) conversion.
"""


def decode_punycode(domain: str) -> str:
    """
    Converts Punycode (xn--...) domain to Cyrillic / Unicode representation.
    Example: 'xn--80apatfnzcq.xn--p1ai' -> 'инфоцифра.рф'
    """
    domain_clean = domain.strip().lower()
    if "xn--" in domain_clean:
        try:
            unicode_domain = domain_clean.encode("ascii").decode("idna")
            return unicode_domain
        except Exception:
            pass
    return domain_clean


def format_domain_display(domain: str) -> str:
    """
    Formats domain string showing both Unicode Cyrillic and Punycode if applicable.
    Example: 'инфоцифра.рф (xn--80apatfnzcq.xn--p1ai)'
    """
    domain_clean = domain.strip().lower()
    if "xn--" in domain_clean:
        try:
            unicode_domain = domain_clean.encode("ascii").decode("idna")
            if unicode_domain != domain_clean:
                return f"{unicode_domain} ({domain_clean})"
        except Exception:
            pass
    return domain_clean
