"""Tests for helper.otx_batch_attrs."""

from helper.otx_batch_attrs import build_pulse_attributes, tlp_security_label


def test_build_pulse_attributes_scalars_and_lists():
    pulse = {
        'id': 'abc123',
        'description': 'A pulse',
        'author_name': 'AlienVault',
        'created': '2026-06-19T11:24:44.247000',
        'modified': '2026-07-19T11:13:46.346000',
        'revision': 3,
        'public': 1,
        'adversary': 'Poisson',
        'references': ['https://example.com/a', 'https://example.com/b'],
        'targeted_countries': ['India', 'Taiwan', 'FooLand'],
        'extract_source': ['src1'],
    }
    attrs = build_pulse_attributes(pulse)
    by_type: dict[str, list[str]] = {}
    for attr_type, value, _displayed in attrs:
        by_type.setdefault(attr_type, []).append(value)

    assert by_type['Description'] == ['A pulse']
    assert by_type['Author'] == ['AlienVault']
    assert by_type['External ID'] == ['abc123']
    assert 'External Date Created' not in by_type
    assert 'External Date Last Modified' not in by_type
    assert 'Report Revision Date' not in by_type
    assert by_type['Availability to Public'] == ['1']
    assert by_type['External References'] == [
        'https://example.com/a',
        'https://example.com/b',
    ]
    assert by_type['Source'] == ['src1']
    assert by_type['Target Country'] == ['India', 'Taiwan, Province Of China']
    assert 'FooLand' not in by_type.get('Target Country', [])
    assert 'Adversary' not in by_type

    desc = next(a for a in attrs if a[0] == 'Description')
    assert desc[2] is True


def test_skip_empty_fields():
    attrs = build_pulse_attributes({'author_name': '  ', 'id': '1'})
    types = [a[0] for a in attrs]
    assert 'Author' not in types
    assert 'External ID' in types


def test_tlp_security_label():
    assert tlp_security_label('white') == 'TLP:WHITE'
    assert tlp_security_label('GREEN') == 'TLP:GREEN'
    assert tlp_security_label('unknown') is None
    assert tlp_security_label(None) is None
