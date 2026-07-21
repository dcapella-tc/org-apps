"""Tests for helper.otx_parse."""

from unittest.mock import MagicMock

from helper.otx_parse import (
    extract_pulses,
    has_next_page,
    merge_page_payloads,
    parse_response_json,
)


def test_extract_pulses_results_key():
    payload = {'results': [{'id': '1'}, {'id': '2'}]}
    assert extract_pulses(payload) == [{'id': '1'}, {'id': '2'}]


def test_extract_pulses_list_key():
    payload = {'list': [{'id': 'a'}]}
    assert extract_pulses(payload) == [{'id': 'a'}]


def test_extract_pulses_empty():
    assert extract_pulses({}) == []
    assert extract_pulses(None) == []
    assert extract_pulses({'results': 'bad'}) == []


def test_has_next_page():
    assert has_next_page({'next': 'https://example/page=2'}) is True
    assert has_next_page({'next_url': '/pulses/subscribed?page=2'}) is True
    assert has_next_page({'next': None, 'next_url': None}) is False
    assert has_next_page({}) is False


def test_merge_page_payloads():
    pages = [
        {'count': 3, 'results': [{'id': '1'}], 'next': 'x'},
        {'results': [{'id': '2'}, {'id': '3'}], 'next': None},
    ]
    merged = merge_page_payloads(pages)
    assert merged['count'] == 3
    assert merged['pages'] == 2
    assert [p['id'] for p in merged['results']] == ['1', '2', '3']


def test_parse_response_json_via_json_method():
    response = MagicMock()
    response.json.return_value = {'list': [{'id': '1'}]}
    assert parse_response_json(response) == {'list': [{'id': '1'}]}


def test_parse_response_json_via_content():
    response = MagicMock()
    response.json.side_effect = ValueError('no json')
    response.content = b'{"results": []}'
    assert parse_response_json(response) == {'results': []}
