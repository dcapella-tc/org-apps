"""Tests for helper.indicators."""

from unittest.mock import MagicMock

from helper.indicators import ENRICHMENT_TAG, fetch_for_pir, has_enrichment_tag


def test_has_enrichment_tag_present():
    ioc = {'tags': {'data': [{'name': 'other'}, {'name': ENRICHMENT_TAG}]}}
    assert has_enrichment_tag(ioc) is True


def test_has_enrichment_tag_absent():
    assert has_enrichment_tag({'tags': {'data': [{'name': 'other'}]}}) is False
    assert has_enrichment_tag({}) is False
    assert has_enrichment_tag({'tags': {}}) is False


def test_fetch_for_pir_builds_request():
    response = MagicMock()
    response.json.return_value = {
        'data': [
            {'id': 1, 'summary': 'evil.example', 'type': 'Host'},
            {'id': 2, 'summary': '1.2.3.4', 'type': 'Address'},
        ]
    }
    response.raise_for_status = MagicMock()
    session = MagicMock()
    session.get.return_value = response

    result = fetch_for_pir(session, '13510798885004707', owner='CTI Lifecycle', result_limit=500)

    assert len(result) == 2
    session.get.assert_called_once_with(
        '/v3/indicators',
        params={
            'tql': (
                'hasGroup(hasIntelRequirement(id=13510798885004707)) '
                'and not hasIntelRequirement(id=13510798885004707)'
            ),
            'sorting': 'calScore DESC',
            'fields': 'tags,associatedGroups',
            'resultLimit': 500,
        },
    )
