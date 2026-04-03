"""TcEx Framework Module"""

# standard library
import threading
from typing import ClassVar


class Singleton(type):
    """A singleton Metaclass"""

    _instances: ClassVar = {}
    _lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        """Evoke call method."""
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]
