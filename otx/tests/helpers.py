"""Shared test helpers for OTX unit tests."""

from unittest.mock import MagicMock


class MockTcExit(Exception):
    """Raised when tests replace ``tcex.exit.exit``."""

    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        super().__init__(msg)


def make_tcex(http_session=None):
    """Build a mocked TcEx with optional external session."""
    tcex = MagicMock()
    if http_session is None:
        http_session = MagicMock()
    external = MagicMock()
    external.__enter__.return_value = http_session
    external.__exit__.return_value = None
    tcex.session.external = external

    def exit_fn(code, msg):
        raise MockTcExit(code, msg)

    tcex.exit.exit.side_effect = exit_fn
    return tcex
