"""Tests for helper.writeback."""

from unittest.mock import MagicMock

from helper.indicators import ENRICHMENT_TAG
from helper.writeback import (
    associated_groups_body,
    build_create_body,
    create_indicator,
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
    body = build_create_body(
        indicator,
        'CTI Lifecycle',
        'polarity results',
        extra_tags=['Finance', 'malware', 'T1059'],
    )
    assert body == {
        'summary': 'evil.example',
        'type': 'Host',
        'ownerName': 'CTI Lifecycle',
        'tags': {
            'data': [
                {'name': 'malware'},
                {'name': ENRICHMENT_TAG},
                {'name': 'Finance'},
                {'name': 'T1059'},
            ]
        },
        'associatedGroups': {
            'data': [{'id': 111}, {'id': 222}],
        },
        'attributes': {
            'data': [
                {
                    'type': 'Description',
                    'value': 'polarity results',
                    'default': True,
                }
            ]
        },
        'sha256': 'a' * 64,
        'md5': 'c' * 32,
    }
    assert 'sha1' not in body


def test_build_create_body_adds_enrichment_tag():
    body = build_create_body(
        {'summary': '1.2.3.4', 'type': 'Address'},
        'Owner',
        'desc',
    )
    assert body['tags']['data'] == [{'name': ENRICHMENT_TAG}]
    assert body['attributes']['data'][0]['value'] == 'desc'


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
    new_id = create_indicator(
        session,
        indicator,
        'CTI Lifecycle',
        'polarity results',
        extra_tags=['Finance'],
    )

    assert new_id == 99
    session.post.assert_called_once_with(
        '/v3/indicators',
        json=build_create_body(
            indicator,
            'CTI Lifecycle',
            'polarity results',
            extra_tags=['Finance'],
        ),
    )
    response.raise_for_status.assert_called_once()
