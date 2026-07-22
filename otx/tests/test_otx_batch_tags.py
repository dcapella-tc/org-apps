"""Tests for helper.otx_batch_tags."""

from helper.otx_batch_tags import build_pulse_tags


def test_build_pulse_tags_country_fallback_only_unmatched():
    pulse = {
        'tags': ['vpn', 'fortinet'],
        'attack_ids': ['T1110'],
        'industries': ['Finance'],
        'adversary': 'Poisson',
        'revision': 3,
        'targeted_countries': [
            'United States of America',
            'India',
            'FooLand',
        ],
    }
    tags = build_pulse_tags(pulse)
    assert 'vpn' in tags
    assert 'T1110' in tags
    assert 'Finance' in tags
    assert 'Poisson' not in tags
    assert 'revision:3' in tags
    # Mapped countries are attributes only — no Target Country tags.
    assert 'Target Country:United States of America' not in tags
    assert 'Target Country:India' not in tags
    assert 'Target Country:FooLand' in tags


def test_revision_tag_skipped_when_empty():
    assert 'revision:' not in ''.join(build_pulse_tags({'revision': ''}))
    assert 'revision:' not in ''.join(build_pulse_tags({}))


def test_empty_lists_ok():
    tags = build_pulse_tags({'tags': ['a'], 'adversary': 'Someone'})
    assert tags == ['a']


def test_dedupe_case_insensitive():
    tags = build_pulse_tags({'tags': ['Foo', 'foo', 'FOO']})
    assert tags == ['Foo']
