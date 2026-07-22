"""Tests for helper.otx_target_country."""

from helper.otx_target_country import map_target_country, resolve_targeted_countries


def test_map_taiwan_alias():
    assert map_target_country('Taiwan') == 'Taiwan, Province Of China'
    assert map_target_country('taiwan') == 'Taiwan, Province Of China'


def test_map_india_exact():
    assert map_target_country('India') == 'India'
    assert map_target_country('INDIA') == 'India'


def test_map_usa_aliases():
    assert map_target_country('United States of America') == 'United States'
    assert map_target_country('USA') == 'United States'
    assert map_target_country('US') == 'United States'


def test_map_unknown_returns_none():
    assert map_target_country('FooLand') is None
    assert map_target_country('  ') is None
    assert map_target_country('') is None


def test_resolve_targeted_countries_splits():
    mapped, unmatched = resolve_targeted_countries(
        {
            'targeted_countries': [
                'Taiwan',
                'India',
                'FooLand',
                'Taiwan',
                'United States of America',
            ]
        }
    )
    assert mapped == [
        'Taiwan, Province Of China',
        'India',
        'United States',
    ]
    assert unmatched == ['FooLand']
