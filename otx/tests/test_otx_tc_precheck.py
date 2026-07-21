"""Tests for helper.otx_tc_precheck."""

from unittest.mock import MagicMock

import pytest

from helper.otx_tc_precheck import assert_owner_batch_writable, batch_create_settings


def test_batch_create_settings_owner():
    settings = batch_create_settings('Capella OTX Source')
    assert settings['owner'] == 'Capella OTX Source'
    assert settings['version'] == 'V2'
    assert settings['action'] == 'Create'


def test_assert_owner_batch_writable_ok():
    session = MagicMock()
    response = MagicMock()
    response.ok = True
    response.status_code = 201
    response.json.return_value = {'status': 'Success', 'data': {'batchId': 1}}
    session.post.return_value = response

    assert_owner_batch_writable(session, 'Capella OTX Source')
    session.post.assert_called_once()
    args, kwargs = session.post.call_args
    assert args[0] == '/v2/batch'
    assert kwargs['json']['owner'] == 'Capella OTX Source'


def test_assert_owner_batch_writable_401():
    session = MagicMock()
    response = MagicMock()
    response.ok = False
    response.status_code = 401
    response.text = (
        'You do not have permission to create Indicators; Groups; Attributes; '
        'Tags; Security Labels.'
    )
    session.post.return_value = response

    with pytest.raises(PermissionError, match='Cannot create batch job'):
        assert_owner_batch_writable(session, 'AlienVault OTX - Subscribed Pulses')


def test_assert_owner_batch_writable_empty_owner():
    with pytest.raises(PermissionError, match='empty'):
        assert_owner_batch_writable(MagicMock(), '  ')
