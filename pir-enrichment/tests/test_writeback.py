"""Tests for helper.writeback."""

from unittest.mock import MagicMock

from helper.indicators import ENRICHMENT_TAG
from helper.writeback import (
    associated_groups_body,
    build_create_body,
    create_indicator,
    set_description,
)


def test_associated_groups_body_id_only():
    indicator = {
        'associatedGroups': {
            'data': [
                {'id': 10, 'name': 'Report A', 'type': 'Report'},
                {'id': 20, 'summary': 'extra'},
                {'name': 'no-id'},
            ]
        }
    }
    assert associated_groups_body(indicator) == {
        'data': [{'id': 10}, {'id': 20}],
    }
    assert associated_groups_body({}) == {'data': []}


def test_set_description_put_body():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    session = MagicMock()
    session.put.return_value = response

    set_description(session, 42, 'polarity results')

    session.put.assert_called_once_with(
        '/v3/indicators/42',
        json={
            'attributes': {
                'data': [
                    {
                        'type': 'Description',
                        'value': 'polarity results',
                        'default': True,
                    }
                ]
            }
        },
    )
    response.raise_for_status.assert_called_once()


def test_build_create_body():
    indicator = {
        'summary': 'evil.example',
        'type': 'Host',
        'tags': {
            'data': [
                {'name': 'malware'},
                {'name': ENRICHMENT_TAG},
                {'name': 'malware'},
            ]
        },
        'associatedGroups': {
            'data': [
                {'id': 111, 'type': 'Report'},
                {'id': 222},
            ]
        },
        'sha256': 'a' * 64,
        'md5': 'c' * 32,
    }
    body = build_create_body(indicator, 'CTI Lifecycle')
    assert body == {
        'summary': 'evil.example',
        'type': 'Host',
        'ownerName': 'CTI Lifecycle',
        'tags': {
            'data': [
                {'name': 'malware'},
                {'name': ENRICHMENT_TAG},
            ]
        },
        'associatedGroups': {
            'data': [{'id': 111}, {'id': 222}],
        },
        'sha256': 'a' * 64,
        'md5': 'c' * 32,
    }
    assert 'sha1' not in body


def test_build_create_body_adds_enrichment_tag():
    body = build_create_body(
        {'summary': '1.2.3.4', 'type': 'Address'},
        'Owner',
    )
    assert body['tags']['data'] == [{'name': ENRICHMENT_TAG}]


def test_create_indicator_posts_body():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {'data': {'id': 99}}
    session = MagicMock()
    session.post.return_value = response

    indicator = {
        'summary': 'evil.example',
        'type': 'Host',
        'associatedGroups': {'data': [{'id': 111}]},
    }
    new_id = create_indicator(session, indicator, 'CTI Lifecycle')

    assert new_id == 99
    session.post.assert_called_once_with(
        '/v3/indicators',
        json=build_create_body(indicator, 'CTI Lifecycle'),
    )
    response.raise_for_status.assert_called_once()
