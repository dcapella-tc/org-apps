"""TcEx Framework Module"""

# standard library
from collections.abc import Callable
from functools import cached_property as functool_cached_property
from typing import ClassVar, Generic, TypeVar

R = TypeVar('R')


class cached_property(functool_cached_property, Generic[R]):  # noqa: N801
    """Customized cached_property."""

    instances: ClassVar = []

    def __init__(self, func: Callable[..., R]):
        """Initialize instance properties."""
        super().__init__(func)

    def __get__(self, instance, owner=None) -> R:  # type: ignore
        """Override method."""
        self.instances.append(instance)
        return super().__get__(instance, owner)  # type: ignore

    @staticmethod
    def _reset():
        """Reset cache"""
        for i in cached_property.instances:
            for key, value in i.__dict__.items():
                if isinstance(value, cached_property):
                    del i.__dict__[key]
