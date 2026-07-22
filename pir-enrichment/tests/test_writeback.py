"""Tests for helper.writeback."""

from unittest.mock import MagicMock

from helper.indicators import ENRICHMENT_TAG
from helper.writeback import (
    add_enrichment_tag,
    associated_groups_body,
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


def test_add_enrichment_tag_put_body():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    session = MagicMock()
    session.put.return_value = response

    indicator = {
        'associatedGroups': {
            'data': [
                {'id': 111, 'type': 'Report'},
                {'id': 222},
            ]
        }
    }
    add_enrichment_tag(session, '99', indicator)

    session.put.assert_called_once_with(
        '/v3/indicators/99',
        json={
            'tags': {
                'data': [
                    {'name': ENRICHMENT_TAG},
                ]
            },
            'associatedGroups': {
                'data': [{'id': 111}, {'id': 222}],
            },
        },
    )
    response.raise_for_status.assert_called_once()
