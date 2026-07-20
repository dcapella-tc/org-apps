"""Tests for helper.otx_api_key.resolve_otx_api_key."""

import pytest

from helper.otx_api_key import resolve_otx_api_key


def test_input_wins_over_env(monkeypatch):
    monkeypatch.setenv('otx_api_key', 'from-env')
    assert resolve_otx_api_key('from-input') == 'from-input'


def test_env_fallback_lowercase(monkeypatch):
    monkeypatch.delenv('OTX_API_KEY', raising=False)
    monkeypatch.setenv('otx_api_key', 'from-env-lower')
    assert resolve_otx_api_key(None) == 'from-env-lower'
    assert resolve_otx_api_key('') == 'from-env-lower'


def test_env_fallback_uppercase(monkeypatch):
    monkeypatch.delenv('otx_api_key', raising=False)
    monkeypatch.setenv('OTX_API_KEY', 'from-env-upper')
    assert resolve_otx_api_key(None) == 'from-env-upper'


def test_placeholder_ignored_uses_env(monkeypatch):
    monkeypatch.setenv('otx_api_key', 'from-env')
    assert resolve_otx_api_key('REPLACE_WITH_OTX_API_KEY') == 'from-env'


def test_missing_raises(monkeypatch):
    monkeypatch.delenv('otx_api_key', raising=False)
    monkeypatch.delenv('OTX_API_KEY', raising=False)
    with pytest.raises(ValueError, match='OTX API key not found'):
        resolve_otx_api_key(None)
    with pytest.raises(ValueError, match='OTX API key not found'):
        resolve_otx_api_key('REPLACE_WITH_OTX_API_KEY')
