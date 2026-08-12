import json
import asyncio
import pytest
from ip2domain.providers.base import BaseProvider
from ip2domain.providers.manager import ProviderManager, register_provider
from ip2domain.exporters import JSONExporter, CSVExporter, TextExporter
from ip2domain.providers.urlscan import URLScanProvider
from ip2domain.providers.virustotal import VirusTotalProvider
from ip2domain.providers.shodan import ShodanProvider
from ip2domain.providers.censys import CensysProvider


class MockProvider(BaseProvider):
    name = "mock"
    description = "Mock Provider for Testing"

    async def lookup_async(self, ip, session):
        return [f"example-{ip.replace('.', '-')}.com"]


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = data
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def json(self, content_type=None):
        return self.data


class FakeSession:
    def __init__(self, data):
        self.data = data

    def get(self, *args, **kwargs):
        return FakeResponse(self.data)


def test_custom_provider_registration():
    register_provider(MockProvider)
    manager = ProviderManager(selected_providers=["mock"])
    assert len(manager.providers) == 1
    assert manager.providers[0].name == "mock"


def test_provider_manager_reads_api_keys_from_environment(monkeypatch):
    monkeypatch.setenv("IP2DOMAIN_VIRUSTOTAL_API_KEY", "vt-secret")
    monkeypatch.setenv("IP2DOMAIN_CENSYS_API_ID", "client")
    monkeypatch.setenv("IP2DOMAIN_CENSYS_API_SECRET", "secret")

    manager = ProviderManager(selected_providers=["virustotal", "censys"])

    assert manager.providers[0].api_key == "vt-secret"
    assert manager.providers[1].api_key == "client:secret"


def test_urlscan_provider_extracts_domains():
    data = {"results": [{
        "page": {"domain": "App.Example.com", "url": "https://app.example.com/"},
        "task": {"domain": "www.example.com"},
    }]}
    result = asyncio.run(URLScanProvider().lookup_async("203.0.113.10", FakeSession(data)))
    assert result == ["app.example.com", "www.example.com"]


def test_virustotal_provider_extracts_resolutions():
    data = {"data": [
        {"attributes": {"host_name": "api.example.com"}},
        {"attributes": {"host_name": "invalid value"}},
    ], "links": {}}
    result = asyncio.run(VirusTotalProvider("key").lookup_async("203.0.113.10", FakeSession(data)))
    assert result == ["api.example.com"]


def test_shodan_and_censys_provider_names():
    shodan_data = {
        "hostnames": ["host.example.com"],
        "domains": ["example.com"],
        "data": [{"hostnames": ["mail.example.com"], "domains": []}],
    }
    shodan = asyncio.run(ShodanProvider("key").lookup_async("203.0.113.10", FakeSession(shodan_data)))
    assert shodan == ["example.com", "host.example.com", "mail.example.com"]

    censys_data = {"result": {"names": ["www.example.com", "bad value"]}}
    censys = asyncio.run(CensysProvider("id:secret").lookup_async("203.0.113.10", FakeSession(censys_data)))
    assert censys == ["www.example.com"]


def test_json_exporter():
    data = [
        {
            "ip": "1.1.1.1",
            "domains": ["one.one.one.one"],
            "provider_details": {"ptr": ["one.one.one.one"]},
            "total_domains": 1,
        }
    ]
    exporter = JSONExporter()
    out = exporter.export(data)
    parsed = json.loads(out)
    assert parsed[0]["ip"] == "1.1.1.1"
    assert parsed[0]["domains"] == ["one.one.one.one"]


def test_csv_exporter():
    data = [
        {
            "ip": "1.1.1.1",
            "domains": ["one.one.one.one"],
            "provider_details": {"ptr": ["one.one.one.one"]},
            "total_domains": 1,
        }
    ]
    exporter = CSVExporter()
    out = exporter.export(data)
    assert "1.1.1.1,one.one.one.one,ptr" in out


def test_text_exporter():
    data = [
        {
            "ip": "1.1.1.1",
            "domains": ["one.one.one.one"],
            "provider_details": {"ptr": ["one.one.one.one"]},
            "total_domains": 1,
        }
    ]
    exporter = TextExporter()
    out = exporter.export(data)
    assert "1.1.1.1" in out
    assert "one.one.one.one" in out
