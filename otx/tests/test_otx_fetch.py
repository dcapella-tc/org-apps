"""Tests for helper.otx_fetch and helper.otx_retry."""

from unittest.mock import MagicMock

import pytest
from tcex.exit import ExitCode

from helper.otx_fetch import fetch_page
from helper.otx_retry import (
    RetryableHttpError,
    call_with_retries,
    is_retryable_status,
)
from tests.helpers import MockTcExit, make_tcex


def test_is_retryable_status():
    assert is_retryable_status(504) is True
    assert is_retryable_status(502) is True
    assert is_retryable_status(401) is False
    assert is_retryable_status(400) is False


def test_call_with_retries_succeeds_after_timeout():
    calls = {'n': 0}
    sleeps: list[float] = []

    def operation(timeout: int):
        calls['n'] += 1
        if calls['n'] < 3:
            raise TimeoutError(f'timeout at {timeout}')
        return f'ok-{timeout}'

    result = call_with_retries(
        operation,
        max_attempts=5,
        sleep_fn=sleeps.append,
    )
    assert result.startswith('ok-')
    assert calls['n'] == 3
    assert len(sleeps) == 2


def test_call_with_retries_retries_504():
    calls = {'n': 0}

    def operation(_timeout: int):
        calls['n'] += 1
        if calls['n'] == 1:
            raise RetryableHttpError(504)
        return 'ok'

    assert call_with_retries(operation, sleep_fn=lambda _: None) == 'ok'
    assert calls['n'] == 2


def test_fetch_page_success():
    http_session = MagicMock()
    response = MagicMock()
    response.ok = True
    http_session.get.return_value = response
    tcex = make_tcex(http_session)

    result = fetch_page(
        tcex,
        path='/pulses/subscribed?page=1',
        headers={'X-OTX-API-KEY': 'k'},
        timeout=60,
    )
    assert result is response
    http_session.get.assert_called_once()


def test_fetch_page_raises_retryable_on_504():
    http_session = MagicMock()
    response = MagicMock()
    response.ok = False
    response.status_code = 504
    http_session.get.return_value = response
    tcex = make_tcex(http_session)

    with pytest.raises(RetryableHttpError) as exc_info:
        fetch_page(
            tcex,
            path='/pulses/subscribed',
            headers={'X-OTX-API-KEY': 'k'},
            timeout=60,
        )
    assert exc_info.value.status_code == 504


def test_fetch_page_exits_on_401():
    http_session = MagicMock()
    response = MagicMock()
    response.ok = False
    response.status_code = 401
    response.text = 'unauthorized'
    http_session.get.return_value = response
    tcex = make_tcex(http_session)

    with pytest.raises(MockTcExit) as exc_info:
        fetch_page(
            tcex,
            path='/pulses/subscribed',
            headers={'X-OTX-API-KEY': 'bad'},
            timeout=60,
        )
    assert exc_info.value.code == ExitCode.FAILURE
    assert '401' in exc_info.value.msg
