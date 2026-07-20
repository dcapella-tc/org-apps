"""Tests for helper.otx_indicator_map."""

from helper.otx_indicator_map import map_otx_indicator


def test_map_hostname():
    mapped = map_otx_indicator(
        {'id': 1, 'type': 'hostname', 'indicator': 'evil.example', 'created': '2026-01-01'}
    )
    assert mapped is not None
    assert mapped.method == 'host'
    assert mapped.kwargs == {'hostname': 'evil.example'}
    assert mapped.otx_id == '1'


def test_map_domain():
    mapped = map_otx_indicator({'type': 'domain', 'indicator': 'bad.com'})
    assert mapped is not None
    assert mapped.method == 'host'


def test_map_url():
    mapped = map_otx_indicator({'type': 'URL', 'indicator': 'https://evil.example/a'})
    assert mapped is not None
    assert mapped.method == 'url'
    assert mapped.kwargs['text'] == 'https://evil.example/a'


def test_map_ipv4():
    mapped = map_otx_indicator({'type': 'IPv4', 'indicator': '1.2.3.4'})
    assert mapped is not None
    assert mapped.method == 'address'
    assert mapped.kwargs['ip'] == '1.2.3.4'


def test_map_file_hashes():
    assert map_otx_indicator({'type': 'FileHash-MD5', 'indicator': 'a' * 32}).kwargs == {
        'md5': 'a' * 32
    }
    assert map_otx_indicator({'type': 'FileHash-SHA1', 'indicator': 'b' * 40}).kwargs == {
        'sha1': 'b' * 40
    }
    assert map_otx_indicator({'type': 'FileHash-SHA256', 'indicator': 'c' * 64}).kwargs == {
        'sha256': 'c' * 64
    }


def test_map_email():
    mapped = map_otx_indicator({'type': 'email', 'indicator': 'a@b.com'})
    assert mapped is not None
    assert mapped.method == 'email_address'


def test_map_unknown_and_empty():
    assert map_otx_indicator({'type': 'CVE', 'indicator': 'CVE-2024-1'}) is None
    assert map_otx_indicator({'type': 'hostname', 'indicator': ''}) is None
    assert map_otx_indicator(None) is None


def test_description_from_title():
    mapped = map_otx_indicator(
        {'type': 'hostname', 'indicator': 'x.com', 'title': 'Title', 'description': ''}
    )
    assert mapped is not None
    assert mapped.description == 'Title'
