from ip2domain.core.engine import LookupEngine


def test_http_name_extraction_ignores_javascript_and_filenames():
    html = """
        document.scripts.length; a.parentNode.insertBefore(k, a);
        <link href="/favicon.ico"><script src="https://mc.yandex.ru/tag.js"></script>
        fetch('//panel.example.com:8443/api');
    """

    assert LookupEngine._extract_http_url_hostnames(html) == {
        "mc.yandex.ru", "panel.example.com"
    }
