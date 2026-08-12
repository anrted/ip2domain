from ip2domain.core.idn_utils import decode_punycode, format_domain_display
from ip2domain.core.graph_builder import GraphBuilder


def test_decode_punycode():
    raw_punycode = "xn--80apatfnzcq.xn--p1ai"
    decoded = decode_punycode(raw_punycode)
    assert decoded == "инфоцифра.рф"


def test_format_domain_display():
    raw_punycode = "xn--80apatfnzcq.xn--p1ai"
    formatted = format_domain_display(raw_punycode)
    assert "инфоцифра.рф" in formatted
    assert "xn--80apatfnzcq.xn--p1ai" in formatted


def test_graph_builder_with_punycode():
    results = [
        {
            "ip": "1.2.3.4",
            "domains": ["xn--80apatfnzcq.xn--p1ai"],
            "open_ports": [],
            "verified_live": True,
        }
    ]
    graph = GraphBuilder.build_graph(results)

    # Label should be decoded Cyrillic: инфоцифра.рф
    apex_node = next(n for n in graph["nodes"] if n["group"] == "apex_domain")
    assert apex_node["label"] == "инфоцифра.рф"
