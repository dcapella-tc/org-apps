"""Tests for helper.publish."""

from unittest.mock import MagicMock

import pytest

from helper.publish import PublishError, parse_request, publish

EXAMPLE = """
{
    "excludedSecurityLabels": ["TLP:AMBER"],
    "owners": ["Capella Community", "Capella Source"],
    "includeTags": true,
    "includeAttributes": true,
    "includeAssociatedIndicators": true,
    "includeAssociatedGroups": true,
    "custom": {
        "source": "security-export-form",
        "group_id": 1234567890
    }
}
"""

SOURCE_FIELDS = [
    'securityLabels',
    'tags',
    'attributes',
    'associatedIndicators',
    'associatedIndicators.securityLabels',
    'associatedGroups',
]
CHILD_FIELDS = [
    'securityLabels',
    'tags',
    'attributes',
    'associatedIndicators',
    'associatedIndicators.securityLabels',
]


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f'HTTP {self.status_code}')


def _xid(parts: list) -> str:
    return 'xid-' + '-'.join(str(part) for part in parts)


def _source() -> dict:
    return {
        'id': 123,
        'type': 'Incident',
        'name': 'Breach',
        'status': 'Open',
        'tags': {'data': [{'name': 'apt'}]},
        'attributes': {'data': [{'type': 'Description', 'value': 'notes', 'default': True}]},
        'securityLabels': {'data': [{'name': 'TLP:GREEN'}, {'name': 'TLP:AMBER'}]},
        'associatedIndicators': {
            'data': [
                {
                    'type': 'Host',
                    'summary': 'evil.example',
                    'securityLabels': {'data': [{'name': 'TLP:WHITE'}, {'name': 'TLP:AMBER'}]},
                },
                {'type': 'File', 'md5': 'a' * 32, 'sha256': 'b' * 64},
            ]
        },
        'associatedGroups': {'data': [{'id': 9, 'type': 'Adversary', 'name': 'Actor'}]},
    }


def _child() -> dict:
    return {
        'id': 9,
        'type': 'Adversary',
        'name': 'Actor',
        'tags': {'data': [{'name': 'actor-tag'}]},
        'securityLabels': {'data': [{'name': 'TLP:GREEN'}]},
    }


class _Api:
    def __init__(self, source: dict, xid_status: int | dict, children: dict | None = None):
        self.source = source
        self.xid_status = xid_status
        self.children = children or {}
        self.calls: list[tuple] = []

    def get(self, url, params=None):
        params = params or {}
        self.calls.append((url, params))
        if 'owner' in params:
            status = self.xid_status
            if isinstance(status, dict):
                status = status[params['owner']]
            payload = {'data': {'id': 1}} if status == 200 else {}
            return _Response(status, payload)
        group_id = str(url.rsplit('/', 1)[-1])
        if group_id == str(self.source['id']):
            return _Response(200, {'data': self.source})
        child = self.children.get(int(group_id))
        if child is None:
            return _Response(404, {})
        return _Response(200, {'data': child})


def _batch():
    batch = MagicMock()
    created = []

    def _obj(*_args, **_kwargs):
        obj = MagicMock()
        created.append(obj)
        return obj

    batch.group.side_effect = _obj
    batch.indicator.side_effect = _obj
    batch.file.side_effect = _obj
    batch.submit_all.return_value = [{}]
    batch.created = created
    return batch


def _factory(batches: list):
    def factory(_owner):
        batch = _batch()
        batches.append(batch)
        return batch

    return factory


def test_parse_request_defaults_update_to_false():
    request = parse_request(EXAMPLE)

    assert request.group_id == 1234567890
    assert request.owners == ['Capella Community', 'Capella Source']
    assert request.update is False
    assert request.include_tags is True
    assert request.include_attributes is True
    assert request.include_indicators is True
    assert request.include_groups is True
    assert request.excluded_security_labels == {'TLP:AMBER'}


def test_skips_existing_owner_when_update_is_false():
    api = _Api(_source(), xid_status=200)
    batches: list = []
    calls: list = []

    def generate_xid(parts):
        calls.append(parts)
        return _xid(parts)

    results = publish(
        api,
        _factory(batches),
        {'owners': ['Capella Community'], 'custom': {'group_id': 123}},
        generate_xid,
    )

    assert calls == [['Capella Community', 'Incident', 'Breach']]
    assert results == [
        {
            'owner': 'Capella Community',
            'xid': 'xid-Capella Community-Incident-Breach',
            'status': 'existing',
        }
    ]
    assert batches == []
    assert ('/v3/groups/xid-Capella Community-Incident-Breach', {'owner': 'Capella Community'}) in (
        api.calls
    )


def test_stages_includes_and_merges_file_hashes():
    api = _Api(_source(), xid_status=404, children={9: _child()})
    batches: list = []
    calls: list = []

    def generate_xid(parts):
        calls.append(parts)
        return _xid(parts)

    results = publish(
        api,
        _factory(batches),
        {
            'owners': ['Capella Community'],
            'excludedSecurityLabels': ['TLP:AMBER'],
            'includeTags': True,
            'includeAttributes': True,
            'includeAssociatedIndicators': True,
            'includeAssociatedGroups': True,
            'custom': {'group_id': 123},
        },
        generate_xid,
    )

    assert results == [
        {
            'owner': 'Capella Community',
            'xid': 'xid-Capella Community-Incident-Breach',
            'status': 'published',
        }
    ]
    assert calls == [
        ['Capella Community', 'Incident', 'Breach'],
        ['Capella Community', 'Adversary', 'Actor'],
    ]
    assert api.calls[0] == ('/v3/groups/123', {'fields': SOURCE_FIELDS})
    assert api.calls[2] == ('/v3/groups/9', {'fields': CHILD_FIELDS})

    batch = batches[0]
    batch.file_merge_mode.assert_called_once_with('Merge')
    batch.group.assert_any_call('Incident', 'Breach', xid='xid-Capella Community-Incident-Breach')
    batch.group.assert_any_call('Adversary', 'Actor', xid='xid-Capella Community-Adversary-Actor')
    batch.indicator.assert_called_once_with('Host', 'evil.example')
    batch.file.assert_called_once_with('a' * 32, None, 'b' * 64)
    batch.submit_all.assert_called_once_with()

    parent, _host, _file, child = batch.created
    parent.tag.assert_called_once_with('apt')
    parent.attribute.assert_called_once_with('Description', 'notes', True)
    parent.add_key_value.assert_called_once_with('status', 'Open')
    assert [call.args[0] for call in parent.security_label.call_args_list] == ['TLP:GREEN']
    child.tag.assert_called_once_with('actor-tag')
    child.association.assert_called_once_with('xid-Capella Community-Incident-Breach')
    _host.association.assert_called_once_with('xid-Capella Community-Incident-Breach')
    _file.association.assert_called_once_with('xid-Capella Community-Incident-Breach')
    assert [call.args[0] for call in _host.security_label.call_args_list] == ['TLP:WHITE']


def test_file_summary_is_split_into_hashes():
    source = {
        'id': 123,
        'type': 'Incident',
        'name': 'Breach',
        'associatedIndicators': {'data': [{'type': 'File', 'summary': 'md5hash :  : sha256hash'}]},
    }
    api = _Api(source, xid_status=404)
    batches: list = []

    publish(
        api,
        _factory(batches),
        {
            'owners': ['Capella Community'],
            'includeAssociatedIndicators': True,
            'custom': {'group_id': 123},
        },
        _xid,
    )

    batches[0].file.assert_called_once_with('md5hash', None, 'sha256hash')
    batches[0].indicator.assert_not_called()


def test_update_true_stages_when_xid_exists():
    api = _Api(_source(), xid_status=200)
    batches: list = []

    results = publish(
        api,
        _factory(batches),
        {'owners': ['Capella Community'], 'update': True, 'custom': {'group_id': 123}},
        _xid,
    )

    assert results[0]['status'] == 'published'
    assert all('owner' not in params for _url, params in api.calls)
    batches[0].group.assert_called_once_with(
        'Incident',
        'Breach',
        xid='xid-Capella Community-Incident-Breach',
    )
    batches[0].submit_all.assert_called_once_with()


def test_false_include_flags_do_not_stage_that_data():
    api = _Api(_source(), xid_status=404, children={9: _child()})
    batches: list = []

    publish(
        api,
        _factory(batches),
        {'owners': ['Capella Community'], 'custom': {'group_id': 123}},
        _xid,
    )

    batch = batches[0]
    parent = batch.created[0]
    parent.tag.assert_not_called()
    parent.attribute.assert_not_called()
    batch.indicator.assert_not_called()
    batch.file.assert_not_called()
    batch.group.assert_called_once()
    assert [call.args[0] for call in parent.security_label.call_args_list] == [
        'TLP:GREEN',
        'TLP:AMBER',
    ]
    assert all(url != '/v3/groups/9' for url, _params in api.calls)


def test_batch_errors_fail_the_publish():
    api = _Api({'id': 123, 'type': 'Incident', 'name': 'Breach'}, xid_status=404)
    batches: list = []

    def factory(_owner):
        batch = _batch()
        batch.submit_all.return_value = [{'errors': ['bad hash']}]
        batches.append(batch)
        return batch

    with pytest.raises(PublishError, match='bad hash'):
        publish(
            api,
            factory,
            {'owners': ['Capella Community'], 'custom': {'group_id': 123}},
            _xid,
        )
