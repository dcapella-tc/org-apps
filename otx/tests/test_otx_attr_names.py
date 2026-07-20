"""Tests for helper.otx_attr_names."""

from helper.otx_attr_names import normalize_attr_name


def test_known_overrides():
    assert normalize_attr_name('targeted_countries') == 'Target Country'
    assert normalize_attr_name('author_name') == 'Author'
    assert normalize_attr_name('created') == 'External Date Created'
    assert normalize_attr_name('modified') == 'External Date Last Modified'
    assert normalize_attr_name('id') == 'External ID'
    assert normalize_attr_name('public') == 'Availability to Public'
    assert normalize_attr_name('references') == 'External References'
    assert normalize_attr_name('extract_source') == 'Source'
    assert normalize_attr_name('description') == 'Description'


def test_adversary_tlp_revision_not_attribute_overrides():
    # Generic Title-Case fallback only; these are no longer attribute mappings.
    assert normalize_attr_name('adversary') == 'Adversary'
    assert normalize_attr_name('tlp') == 'Tlp'
    assert normalize_attr_name('revision') == 'Revision'


def test_generic_snake_case():
    assert normalize_attr_name('some_new_field') == 'Some New Field'
    assert normalize_attr_name('foo-bar') == 'Foo Bar'


def test_empty():
    assert normalize_attr_name('') == ''
    assert normalize_attr_name('   ') == ''
