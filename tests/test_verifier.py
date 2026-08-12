import asyncio
from ip2domain.core.verifier import DomainVerifier


def test_live_domain_verifier(monkeypatch):
    async def fake_resolve(domain, timeout=5.0):
        return {"1.1.1.1", "2606:4700:4700::1111"}

    monkeypatch.setattr(DomainVerifier, "resolve_domain", fake_resolve)
    async def _test():
        is_live = await DomainVerifier.verify_domain("one.one.one.one", "1.1.1.1")
        assert is_live is True

        # Check non-matching IP
        is_not_matching = await DomainVerifier.verify_domain("one.one.one.one", "8.8.8.8")
        assert is_not_matching is False

    asyncio.run(_test())


def test_wildcard_dns_candidates_are_rejected(monkeypatch):
    async def fake_resolve(domain, timeout=5.0):
        if domain == "ae0.ru":
            return {"31.135.32.233"}
        if domain.endswith(".ae0.ru"):
            return {"31.135.32.233"}
        return set()

    monkeypatch.setattr(DomainVerifier, "resolve_domain", fake_resolve)

    async def _test():
        resolved, rejected = await DomainVerifier.resolve_domains(
            ["ae0.ru", "forumfz.ae0.ru", "www.ae0.ru"]
        )
        assert resolved == {"ae0.ru": {"31.135.32.233"}}
        assert rejected == {"forumfz.ae0.ru", "www.ae0.ru"}

        live = await DomainVerifier.filter_live_domains(
            ["ae0.ru", "forumfz.ae0.ru"], "31.135.32.233"
        )
        assert live == ["ae0.ru"]

    asyncio.run(_test())


def test_explicit_subdomain_different_from_wildcard_is_kept(monkeypatch):
    async def fake_resolve(domain, timeout=5.0):
        if domain == "real.example.com":
            return {"203.0.113.20"}
        if domain == "example.com":
            return {"203.0.113.10"}
        if domain.endswith(".example.com"):
            return {"203.0.113.10"}
        return set()

    monkeypatch.setattr(DomainVerifier, "resolve_domain", fake_resolve)

    async def _test():
        resolved, rejected = await DomainVerifier.resolve_domains(
            ["example.com", "real.example.com", "ghost.example.com"]
        )
        assert resolved["example.com"] == {"203.0.113.10"}
        assert resolved["real.example.com"] == {"203.0.113.20"}
        assert "ghost.example.com" in rejected

    asyncio.run(_test())
