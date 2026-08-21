"""Tests for City IP Finder API and Geo City Database."""
import pytest
from fastapi.testclient import TestClient

from ip2domain.data.geo_city_db import geo_city_db
from ip2domain.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_geo_city_db_basics():
    summary = geo_city_db.get_countries_summary()
    assert len(summary) == 2
    ru = next(c for c in summary if c["code"] == "RU")
    by = next(c for c in summary if c["code"] == "BY")
    assert ru["subnets"] > 1000
    assert ru["ip_count"] > 1000000
    assert by["subnets"] > 500
    assert by["ip_count"] > 500000


def test_geo_city_db_novokuznetsk():
    subnets, total = geo_city_db.filter_subnets(city="Новокузнецк")
    assert total >= 40
    assert any("Rostelecom" in s["org"] or "Sibirskie" in s["org"] or "E-Light" in s["org"] or "Ray-Svyaz" in s["org"] for s in subnets)


def test_geo_city_db_all_cidrs():
    cidrs = geo_city_db.get_all_cidrs_for_filter(city="Новокузнецк")
    assert len(cidrs) >= 40
    for c in cidrs:
        assert "/" in c


def test_geo_city_db_find_by_ip():
    res = geo_city_db.find_by_ip("31.135.32.1")
    assert res is not None
    assert "Новокузнецк" in res["city"] or "Novokuznetsk" in res.get("city_en", "")


def test_api_countries(client):
    resp = client.get("/api/geo/countries")
    assert resp.status_code == 200
    data = resp.json()
    assert "countries" in data
    assert len(data["countries"]) == 2


def test_api_subnets_novokuznetsk(client):
    resp = client.get("/api/geo/subnets?city=Новокузнецк&limit=50")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 40
    assert len(data["subnets"]) >= 40


def test_api_all_cidrs_endpoint(client):
    resp = client.get("/api/geo/all-cidrs?city=Новокузнецк")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 40
    assert len(data["cidrs"]) >= 40


def test_camera_result_geo_fields():
    from ip2domain.cameras.scanner_v2.models import CameraResult
    cam = CameraResult(ip="31.135.32.1", brand="Hikvision")
    geo = geo_city_db.find_by_ip(cam.ip)
    assert geo is not None
    cam.city = geo["city"]
    cam.region = geo["region"]
    cam.country_code = geo["country_code"]
    cam.isp = geo["isp"]

    d = cam.to_dict()
    assert d["city"] == "Новокузнецк"
    assert d["country_code"] == "RU"


def test_api_resolve_geo(client):
    resp = client.post("/api/v2/resolve_geo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True

