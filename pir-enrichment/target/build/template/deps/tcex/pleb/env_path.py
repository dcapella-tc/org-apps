"""TcEx Framework Module"""

# standard library
import os
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any


class _EnvPath(type(Path()), Path):  # type: ignore
    """A stub of Path with additional attribute."""

    # store for the original value passed to EnvPath
    original_value: str | None = None


class EnvPath(Path):
    """EnvPath custom pydantic model type."""

    @classmethod
    def __modify_schema__(cls, field_schema: dict[str, Any]):
        """."""
        field_schema.update(format='file-path')

    @classmethod
    def __get_validators__(cls) -> Generator:
        """."""
        yield cls.validate

    @classmethod
    def validate(cls, value: Path | str) -> Path | str:
        """Replace any environment variables in the tcex.json file."""
        if isinstance(value, Path):
            return value

        string = str(value)
        for m in re.finditer(r'\${(env|envs|local|remote):(.*?)}', string):
            try:
                full_match = m.group(0)
                env_type = m.group(1)
                env_key = m.group(2)

                if env_type != 'env':
                    ex_msg = f'Invalid environment type found ({env_type})'
                    raise ValueError(ex_msg)
                env_value = os.getenv(env_key)
                if env_value is not None:
                    string = string.replace(full_match, env_value)
            except IndexError:
                return string

        # convert value to Path and return original value
        p = _EnvPath(Path(string).expanduser())
        p.original_value = value
        return p
