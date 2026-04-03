"""TcEx Framework Module"""

from .singleton import Singleton


class NoneModel(metaclass=Singleton):
    """A dummy model that return None for all attribute requests."""

    def __getattribute__(self, _: str):
        """Return None for any attribute request."""
        return
