import tempfile
import pytest
from ip2domain.core.ip_parser import IPParser


def test_single_ip_parsing():
    ips = list(IPParser.parse_target("8.8.8.8"))
    assert ips == ["8.8.8.8"]


def test_cidr_parsing():
    ips = list(IPParser.parse_target("192.168.1.0/30"))
    # Host IP addresses in /30: .1, .2
    assert ips == ["192.168.1.1", "192.168.1.2"]

    ips_32 = list(IPParser.parse_target("10.0.0.1/32"))
    assert ips_32 == ["10.0.0.1"]


def test_range_parsing():
    ips = list(IPParser.parse_target("10.0.0.1-10.0.0.4"))
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_invalid_range_raises():
    with pytest.raises(ValueError):
        list(IPParser.parse_target("10.0.0.5-10.0.0.1"))


def test_invalid_ip_raises():
    with pytest.raises(ValueError):
        list(IPParser.parse_target("999.999.999.999"))


def test_large_target_is_rejected():
    with pytest.raises(ValueError, match="maximum"):
        list(IPParser.parse_target("10.0.0.0/8"))


def test_file_parsing():
    content = """
    # Comment line
    8.8.8.8
    1.1.1.1-1.1.1.2
    192.168.1.0/30
    """
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(content)
        tmp.flush()
        parsed = list(IPParser.parse_file(tmp.name))

    assert "8.8.8.8" in parsed
    assert "1.1.1.1" in parsed
    assert "1.1.1.2" in parsed
    assert "192.168.1.1" in parsed
    assert "192.168.1.2" in parsed
