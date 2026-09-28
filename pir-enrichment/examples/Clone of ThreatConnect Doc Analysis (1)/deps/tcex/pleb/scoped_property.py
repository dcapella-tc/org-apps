"""Declares a scoped_property decorator."""

# standard library
import os
import threading
from collections.abc import Callable
from typing import Any, ClassVar, Generic, TypeVar

T = TypeVar('T')


class scoped_property(Generic[T]):  # noqa: N801
    """Makes a value unique for each thread and also acts as a @property decorator.

    Essentially, a thread-and-process local value.  When used to decorate a function, will
    treat that function as a factory for the underlying value, and will invoke it to produce a value
    for each thread the value is requested from.

    Note that this also provides a cache: each thread will reuse the value previously created
    for it.
    """

    instances: ClassVar = []

    def __init__(self, wrapped: Callable[..., T]):
        """Initialize the instance properties."""
        scoped_property.instances.append(self)
        self.wrapped = wrapped
        self.value = threading.local()

    def __del__(self):
        """Remove instance from the instances class variable when it's destroyed."""
        scoped_property.instances = [i for i in scoped_property.instances if i != self]

    def __get__(self, instance: Any, _: Any) -> T:
        """Return a thread-and-process-local value.

        Implementation per the descriptor protocol.

        Args:
            instance: the instance this property is being resolved for.
            owner: same as instance.
        """
        if hasattr(self.value, 'data'):
            # A value has been created for this thread already, but we have to make sure we're in
            # the same process (threads are duplicated when a process is forked).
            pid, value, stored_instance = self.value.data

            # create a new instance if the following are not true:
            # 1. Check for same pid
            # 2. Check to ensure stored instance is the same as the current instance
            if pid != os.getpid() or stored_instance is not instance:
                return self._create_value(instance, self.wrapped)

            return value

        # A value has *not* been created for the calling thread
        # yet, so use the factory to create a new one.
        return self._create_value(instance, self.wrapped)

    def _create_value(self, instance, wrapped, *args, **kwargs) -> T:
        """Call the wrapped factory function to get a new value."""
        data = wrapped(instance, *args, **kwargs) if instance else wrapped(*args, **kwargs)

        # add data to threat.local
        self.value.data = os.getpid(), data, instance

        return data

    @staticmethod
    def _reset():
        for i in scoped_property.instances:
            i.value = threading.local()
