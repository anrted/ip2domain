import pytest
from ip2domain.core.domain_recon import DomainReconEngine


def test_is_domain_target():
    assert DomainReconEngine.is_domain_target("example.com") is True
    assert DomainReconEngine.is_domain_target("sub.domain.co.uk") is True
    assert DomainReconEngine.is_domain_target("grinronn.ru") is True
    assert DomainReconEngine.is_domain_target("xn--e1afmkfd.xn--p1ai") is True

    # False cases
    assert DomainReconEngine.is_domain_target("1.1.1.1") is False
    assert DomainReconEngine.is_domain_target("192.168.1.0/24") is False
    assert DomainReconEngine.is_domain_target("10.0.0.1-10.0.0.5") is False
    assert DomainReconEngine.is_domain_target("") is False


def test_domain_recon_run(monkeypatch):
    import asyncio
    engine = DomainReconEngine(concurrency=5)

    async def fake_discover(domain, progress_callback=None):
        return {"www.one.one.one.one"}

    async def fake_resolve(subdomains, progress_callback=None):
        return ({"1.1.1.1": set(subdomains)}, {d: {"1.1.1.1"} for d in subdomains})

    monkeypatch.setattr(engine, "_discover_all_subdomains", fake_discover)
    monkeypatch.setattr(engine, "_resolve_subdomains_to_ips", fake_resolve)
    results = asyncio.run(engine.run_domain_recon("one.one.one.one"))
    assert isinstance(results, list)
    assert len(results) > 0
    first = results[0]
    assert "ip" in first
    assert "domains" in first
    assert "one.one.one.one" in first["domains"]


def test_axfr_names_are_added_to_discovery(monkeypatch):
    import asyncio

    engine = DomainReconEngine()

    async def fake_axfr(domain):
        return {domain, f"sales.{domain}", f"random-name.{domain}"}

    async def empty_source(domain):
        return set()

    monkeypatch.setattr(engine, "_fetch_axfr_subdomains", fake_axfr)
    monkeypatch.setattr(engine, "_fetch_crtsh_subdomains", empty_source)
    monkeypatch.setattr(engine, "_fetch_hackertarget_subdomains", empty_source)
    monkeypatch.setattr(engine, "_fetch_subdomaincenter_subdomains", empty_source)
    monkeypatch.setattr(engine, "_fetch_certspotter_subdomains", empty_source)
    monkeypatch.setattr(engine, "_probe_common_subdomains", empty_source)

    discovered = asyncio.run(engine._discover_all_subdomains("example.com"))

    assert discovered == {
        "example.com", "sales.example.com", "random-name.example.com"
    }


def test_successful_axfr_extracts_only_in_scope_names():
    class FakeZone:
        nodes = {
            "example.com.": object(),
            "sales.example.com.": object(),
            "random-name.example.com.": object(),
            "*.example.com.": object(),
            "outside.test.": object(),
        }

    result = DomainReconEngine._extract_axfr_names(FakeZone(), "example.com")

    assert result == {
        "example.com", "sales.example.com", "random-name.example.com"
    }
