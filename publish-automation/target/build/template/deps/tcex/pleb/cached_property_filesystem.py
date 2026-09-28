"""TcEx Framework Module"""

import contextlib
import logging
import os
import pickle  # nosec
import tempfile
import time
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Generic, TypeVar

import wrapt

from ..logger.trace_logger import TraceLogger

if TYPE_CHECKING:
    from collections.abc import Callable

R = TypeVar('R')

_logger: TraceLogger = logging.getLogger(__name__.split('.', maxsplit=1)[0])  # type: ignore


class cached_property_filesystem(Generic[R]):  # noqa: N801
    """Cached property backed by both in-memory and filesystem storage.

    Both layers share a single ``ttl``.  In the main process the memory cache
    serves the value directly.  The filesystem layer exists so that **forked
    processes** can read the cached value from disk on their first access
    instead of making a redundant API call.

    On access the decorator checks:

    1. **Memory** - if the value is cached and within ``ttl`` seconds, return it.
    2. **Filesystem** - if a cache file exists and is within ``ttl`` seconds,
       store it in memory and return it.
    3. **Compute** - call the wrapped function, store the result in both layers,
       and return.

    Writes to the filesystem are atomic (write-to-temp then rename) so that
    forked processes never observe a partially-written cache file.

    Example::

        @cached_property_filesystem(ttl=86400)
        def expensive(self) -> dict:
            return fetch_from_api()

    Attributes:
        instances: Class-level weak set of instances that currently hold an
            in-memory cache entry, used by ``_reset`` to clear all caches.
            Weak references allow instances to be garbage collected normally.
    """

    instances: ClassVar[weakref.WeakSet] = weakref.WeakSet()

    def __init__(self, ttl: int = 86_400):
        """Initialize the decorator.

        Args:
            ttl: Seconds before the cached value expires in both memory and on
                disk (default is 86_400 or 24 hours).
        """
        self.ttl = ttl
        self.attr_name: str | None = None
        self._wrapper: Any = None

    # ------------------------------------------------------------------
    # Descriptor protocol
    # ------------------------------------------------------------------

    def __call__(self, func: 'Callable[..., R]') -> 'cached_property_filesystem[R]':
        """Register the wrapped function when used as ``@cached_property_filesystem(...)``.

        Args:
            func: The method to wrap.

        Returns:
            This descriptor instance.
        """
        self.attr_name = func.__name__  # ty: ignore[unresolved-attribute]
        self.__doc__ = func.__doc__
        self._wrapper = self._make_wrapper(func)
        return self

    def __set_name__(self, owner: type, name: str) -> None:
        """Capture the attribute name assigned on the owning class.

        Args:
            owner: The class this descriptor is assigned to.
            name: The attribute name on *owner*.
        """
        self.attr_name = name

    def __get__(self, instance: Any, owner: type | None = None) -> R:
        """Return the cached value, falling back through memory, filesystem, then compute.

        Args:
            instance: The object this property is accessed on, or ``None`` for class access.
            owner: The owning class.

        Returns:
            The cached or freshly computed value.
        """
        if instance is None:
            return self  # ty: ignore[invalid-return-type]

        return self._wrapper.__get__(instance, owner)()

    # ------------------------------------------------------------------
    # Wrapper creation
    # ------------------------------------------------------------------

    def _make_wrapper(self, func: 'Callable[..., R]') -> Any:
        """Create a wrapt-decorated wrapper with caching logic.

        Args:
            func: The method to wrap.

        Returns:
            A wrapt-wrapped function that implements the caching logic.
        """
        cpf = self
        read_fs_cache = self._read_fs_cache

        @wrapt.decorator
        def wrapper(*wrapped_args) -> R:  # noqa: D417
            """Implement caching wrapper for decorator.

            Args:
                wrapped (callable): The wrapped function which in turns
                    needs to be called by your wrapper function.
                instance (object): The object to which the wrapped
                    function was bound when it was called.
                args (list): The list of positional arguments supplied
                    when the decorated function was called.
                kwargs (dict): The dictionary of keyword arguments
                    supplied when the decorated function was called.

            Returns:
                The cached or freshly computed value.
            """
            # using wrapped args to support typing hints in the type checker
            wrapped: Callable = wrapped_args[0]
            instance: Any = wrapped_args[1]
            args: list = wrapped_args[2] if len(wrapped_args) > 1 else []
            kwargs: dict = wrapped_args[3] if len(wrapped_args) > 2 else {}  # noqa: PLR2004

            now = time.time()
            cache_key = f'__cache_fs_{cpf.attr_name}'

            # --- layer 1: memory cache ---
            cached: tuple[float, R] | None = instance.__dict__.get(cache_key)
            if cached is not None:
                timestamp, value = cached
                if now - timestamp < cpf.ttl:
                    return value

            # --- layer 2: filesystem cache (primary benefit for forked processes) ---
            cache_path = cached_property_filesystem._cache_path(instance, cpf.attr_name)
            fs_cache = read_fs_cache(cache_path, now)
            if fs_cache is not None:
                last_fetched_timestamp, value = fs_cache
                instance.__dict__[cache_key] = (last_fetched_timestamp, value)
                cached_property_filesystem.instances.add(instance)
                return value

            # --- miss: compute and store in both layers ---
            value = wrapped(*args, **kwargs)

            now = time.time()
            instance.__dict__[cache_key] = (now, value)
            cached_property_filesystem.instances.add(instance)
            cached_property_filesystem._write_fs_cache(cache_path, value, now)

            return value

        return wrapper(func)

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_path(instance: Any, attr_name: str | None) -> Path:
        """Build the filesystem path for this property's cache file.

        In the `_set_temp_dir` method of `tcex.input.input.Input` the system temp directory is
        set to a private location for each app run, so we can safely store cache files there
        without worrying about the `tmp` directory being system writable by other users and
        arbitrary code execution risks.

        Args:
            instance: The object this property belongs to.
            attr_name: The attribute name for the cache key.

        Returns:
            A ``Path`` under the system temp directory.
        """
        cache_dir = Path(tempfile.gettempdir()) / 'tcex_cache'
        return cache_dir / f'{type(instance).__name__}_{attr_name}.pkl'

    def _read_fs_cache(self, path: Path, now: float) -> tuple[float, R] | None:
        """Read and validate the filesystem cache.

        Args:
            path: The cache file to read.
            now: The current timestamp for TTL comparison.

        Returns:
            The cached value if valid, or ``None`` on miss or error.
        """
        if not path.is_file():
            return None

        try:
            raw = pickle.loads(path.read_bytes())  # nosec
            if now - raw['timestamp'] < self.ttl:
                return raw['timestamp'], raw['value']
        except Exception as ex:
            _logger.warning(f'cached_property_filesystem: failed to read {path}: {ex}')

        return None

    @staticmethod
    def _write_fs_cache(path: Path, value: Any, now: float) -> None:
        """Persist a value to the filesystem cache using an atomic rename.

        Writes to a temporary file first and then renames it to the target
        path so that concurrent readers in forked processes never observe a
        partially-written file.

        Args:
            path: The target cache file path.
            value: The value to persist (must be picklable).
            now: The timestamp to store alongside the value.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            fd, tmp_path_str = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
            tmp_path = Path(tmp_path_str)
            try:
                with os.fdopen(fd, 'wb') as fh:
                    pickle.dump({'timestamp': now, 'value': value}, fh)
                tmp_path.rename(path)
            except BaseException:
                with contextlib.suppress(OSError):
                    tmp_path.unlink()
                raise
        except OSError as ex:
            _logger.warning(f'cached_property_filesystem: failed to write {path}: {ex}')
        except Exception as ex:
            _logger.warning(f'cached_property_filesystem: unexpected error writing {path}: {ex}')

    # ------------------------------------------------------------------
    # Reset support (mirrors cached_property pattern)
    # ------------------------------------------------------------------

    @staticmethod
    def _reset() -> None:
        """Clear all in-memory caches and remove filesystem cache files."""
        for instance in cached_property_filesystem.instances:
            for key in list(instance.__dict__):
                if key.startswith('__cache_fs_'):
                    del instance.__dict__[key]
        cached_property_filesystem.instances.clear()

        # remove all filesystem cache files
        cache_dir = Path(tempfile.gettempdir()) / 'tcex_cache'
        if cache_dir.is_dir():
            for cache_file in cache_dir.glob('*.pkl'):
                with contextlib.suppress(OSError):
                    cache_file.unlink()
