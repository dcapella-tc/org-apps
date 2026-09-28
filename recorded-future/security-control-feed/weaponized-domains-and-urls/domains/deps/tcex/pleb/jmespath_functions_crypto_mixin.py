"""Cryptographic and identity functions for ThreatConnect JMESPath custom functions."""

import uuid as uuid_module

import semantic_version
from jmespath import functions

from .jmespath_functions_base import JmespathFunctionsBase


class CryptoFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing cryptographic and identity JMESPath functions.

    Functions: semver_compare, uuid, uuid5.
    """

    @functions.signature({'types': ['string']}, {'types': ['string']})
    def _func_semver_compare(self, base_version: str, comparison_spec: str) -> bool:
        """Compare a semantic version string against a version constraint expression.

        The constraint may use operators: >, >=, <, <=, ==, !=.
        Multiple constraints can be combined (e.g., '>=1.2.0,<2.0.0').

        Expression:
        semver_compare(app_version, '>=1.0.0,<2.0.0')

        Data:
        {"app_version": "1.5.3"}

        Output:
        true
        """
        spec = semantic_version.SimpleSpec(comparison_spec)
        version = semantic_version.Version(base_version)
        return version in spec

    @functions.signature()
    def _func_uuid(self) -> str:
        """Generate a random UUID4 string.

        Expression:
        uuid()

        Output:
        "3264b35c-ff5d-44a8-8bc7-9be409dac2b7"
        """
        return str(uuid_module.uuid4())

    @functions.signature({'types': ['string']})
    def _func_uuid5(self, input_: str) -> str:
        """Generate a deterministic UUID5 from a string using the DNS namespace.

        Returns the same UUID for the same input, making it suitable for
        generating stable identifiers from known values such as host names or titles.

        Expression:
        uuid5(title)

        Data:
        {"title": "my-article"}

        Output:
        "408f94e1-44a9-5e57-a20b-7e5356de87a9"
        """
        return str(uuid_module.uuid5(uuid_module.NAMESPACE_DNS, input_))
