import pytest

from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.scope import ScanPlan, TargetScope, parse_ports


def test_scope_merges_and_excludes_without_expansion():
    scope = TargetScope("192.0.2.0/24\n192.0.2.4\n2001:db8::/126", "192.0.2.1-192.0.2.254\n2001:db8::1")
    assert scope.count == 5
    assert [scope.address(i) for i in range(5)] == [
        "192.0.2.0", "192.0.2.255", "2001:db8::", "2001:db8::2", "2001:db8::3",
    ]
    assert not scope.contains("192.0.2.100")
    assert scope.contains("2001:db8::2")


def test_large_scope_is_constant_size():
    scope = TargetScope("2001:db8::/64")
    assert scope.count == 2 ** 64
    assert len(scope.ranges) == 1
    assert scope.address(scope.count - 1) == "2001:db8::ffff:ffff:ffff:ffff"


@pytest.mark.parametrize("target", ["example.com", "224.0.0.0/4", "::", "0.0.0.0", "192.0.2.4-192.0.2.1"])
def test_invalid_or_unsafe_scope(target):
    with pytest.raises(ValueError):
        TargetScope(target)


def test_full_range_plan_and_tcp_udp_identity():
    config = ScanConfig(targets="192.0.2.1", profile="full_tcp")
    plan = config.plan()
    assert plan.endpoint_count == 65535
    assert plan.block(0).ports[0] == 1
    assert plan.block(plan.total - 1).ports[-1] == 65535
    plan = ScanPlan(TargetScope("192.0.2.1-192.0.2.2"), (80,), (80,), 1)
    assert [(plan.block(i).ip, plan.block(i).transport) for i in range(4)] == [
        ("192.0.2.1", "tcp"), ("192.0.2.1", "udp"),
        ("192.0.2.2", "tcp"), ("192.0.2.2", "udp"),
    ]


@pytest.mark.parametrize("value", ["0", "65536", "80-1", "abc", "-1"])
def test_invalid_ports(value):
    with pytest.raises(ValueError):
        parse_ports(value)


def test_port_deduplication():
    assert parse_ports("80,80-82,81,443") == (80, 81, 82, 443)


@pytest.mark.parametrize("values", [
    {"profile": "deep_identification"},
    {"udp_ports": "53"},
    {"nmap": True},
    {"workers": 0},
    {"workers": 1.5},
    {"rate": float("nan")},
    {"network_id": "../invalid"},
    {"hostname": "example.com\r\nX-Evil: yes"},
])
def test_policy_rejects_invalid_or_implicit_active_probes(values):
    with pytest.raises(ValueError):
        ScanConfig(targets="192.0.2.1", **values)


def test_plan_requires_explicit_scale_budget():
    with pytest.raises(ValueError, match="max_endpoints"):
        ScanConfig(targets="2001:db8::/64").plan()
