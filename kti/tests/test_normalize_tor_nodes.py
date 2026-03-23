"""Tests for Fusion Tor JSON normalization."""

from app import normalize_tor_nodes_payload


def test_normalize_top_level_list():
    data = [{'ip': '1.1.1.1', 'name': 'n', 'flags': 'F'}]
    assert normalize_tor_nodes_payload(data) == data


def test_normalize_wrapped_in_data_key():
    inner = [{'ip': '2.2.2.2'}]
    assert normalize_tor_nodes_payload({'data': inner}) == inner


def test_normalize_single_object_with_ip():
    row = {'ip': '3.3.3.3', 'flags': 'X'}
    assert normalize_tor_nodes_payload(row) == [row]


def test_normalize_unknown_shape_returns_empty():
    assert normalize_tor_nodes_payload({}) == []
    assert normalize_tor_nodes_payload('not-json') == []
