"""Tests for helper.type_map."""

from helper.type_map import map_polarity_type


def test_map_host():
    assert map_polarity_type({'type': 'Host', 'summary': 'evil.example'}) == 'domain'


def test_map_address_ipv4():
    assert map_polarity_type({'type': 'Address', 'ip': '1.2.3.4'}) == 'IPv4'


def test_map_address_ipv6():
    assert map_polarity_type({'type': 'Address', 'ip': '2001:db8::1'}) == 'IPv6'


def test_map_address_falls_back_to_summary():
    assert map_polarity_type({'type': 'Address', 'summary': '2001:db8::2'}) == 'IPv6'


def test_map_file_prefers_sha256():
    assert (
        map_polarity_type(
            {
                'type': 'File',
                'sha256': 'a' * 64,
                'sha1': 'b' * 40,
                'md5': 'c' * 32,
            }
        )
        == 'SHA256'
    )


def test_map_file_sha1():
    assert map_polarity_type({'type': 'File', 'sha1': 'b' * 40}) == 'SHA1'


def test_map_file_md5():
    assert map_polarity_type({'type': 'File', 'md5': 'c' * 32}) == 'MD5'


def test_map_file_no_hashes():
    assert map_polarity_type({'type': 'File', 'summary': 'x'}) is None


def test_map_email_types():
    assert map_polarity_type({'type': 'EmailAddress', 'summary': 'a@b.c'}) == 'email'
    assert map_polarity_type({'type': 'Email Subject', 'summary': 'phish'}) == 'email'


def test_map_url():
    assert map_polarity_type({'type': 'URL', 'summary': 'https://x'}) == 'url'


def test_map_unknown():
    assert map_polarity_type({'type': 'ASN', 'summary': 'AS123'}) is None
