"""Tests for helper.polarity."""

from unittest.mock import MagicMock

from helper.polarity import (
    build_auth_headers,
    build_lookup_body,
    list_integrations,
    lookup_all,
    matching_ids,
)


def test_build_auth_headers():
    headers = build_auth_headers('secret')
    assert headers['Authorization'] == 'Bearer secret'
    assert headers['Accept'] == 'application/vnd.api+json'
    assert headers['Content-Type'] == 'application/vnd.api+json'


def test_build_lookup_body():
    body = build_lookup_body('evil.example', 'domain')
    assert body == {
        'data': {
            'type': 'integration-lookups',
            'attributes': {
                'entities': [{'value': 'evil.example', 'type': 'domain'}],
            },
        }
    }


def test_matching_ids_filters_by_type():
    payload = {
        'data': [
            {
                'id': '10',
                'attributes': {
                    'integration-entity-types': [
                        {'key': 'domain', 'integration_id': '10'},
                        {'key': 'IPv4', 'integration_id': '10'},
                    ]
                },
            },
            {
                'id': '20',
                'attributes': {
                    'integration-entity-types': [
                        {'key': 'IPv4', 'integration_id': '20'},
                    ]
                },
            },
            {
                'id': '30',
                'attributes': {
                    'integration-entity-types': [
                        {'key': 'url', 'integration_id': '30'},
                    ]
                },
            },
        ]
    }
    assert matching_ids(payload, 'domain') == ['10']
    assert matching_ids(payload, 'IPv4') == ['10', '20']
    assert matching_ids(payload, 'SHA256') == []


def test_list_integrations():
    response = MagicMock()
    response.json.return_value = {'data': []}
    response.raise_for_status = MagicMock()
    session = MagicMock()
    session.get.return_value = response

    headers = build_auth_headers('k')
    assert list_integrations(session, headers) == {'data': []}
    session.get.assert_called_once_with('/integrations', headers=headers)


def test_lookup_all_concatenates_and_continues_on_error():
    ok = MagicMock()
    ok.ok = True
    ok.text = '{"ok":1}'

    bad = MagicMock()
    bad.ok = False
    bad.status_code = 500
    bad.reason = 'Server Error'

    session = MagicMock()
    session.post.side_effect = [ok, bad, Exception('timeout'), ok]

    log = MagicMock()
    content = lookup_all(
        session,
        build_auth_headers('k'),
        ['1', '2', '3', '4'],
        'evil.example',
        'domain',
        log=log,
    )

    assert content == '{"ok":1}\n{"ok":1}'
    assert session.post.call_count == 4
    assert log.warning.call_count == 2
