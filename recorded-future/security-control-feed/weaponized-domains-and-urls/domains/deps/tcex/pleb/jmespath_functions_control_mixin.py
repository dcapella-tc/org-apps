"""Control flow functions for ThreatConnect JMESPath custom functions."""

from typing import Any

from jmespath import functions

from .jmespath_functions_base import JmespathFunctionsBase


class ControlFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing control flow JMESPath functions.

    Functions: has_value, in, ternary, type.
    """

    @functions.signature({'types': []})
    def _func_has_value(self, entry: Any) -> bool:
        """Return true if the entry is truthy using standard Python bool() rules.

        Rules: null → false; boolean false → false; empty string → false;
        zero → false; all other values → true.

        Expression:
        has_value(status)

        Data:
        {"status": "active"}

        Output:
        true
        """
        return bool(entry)

    @functions.signature({'types': []}, {'types': ['array']})
    def _func_in(self, element: Any, array: list) -> bool:
        """Check whether an element exists in a list.

        Expression:
        in(status, ["active", "pending"])

        Data:
        {"status": "active"}

        Output:
        true
        """
        return element in set(array)

    @functions.signature({'types': []}, {'types': []}, {'types': []})
    def _func_ternary(self, test: Any, if_true: Any, if_false: Any) -> Any:
        """Return if_true when test is truthy, otherwise if_false (ternary operator).

        Expression:
        ternary(contains(tags, 'critical'), 'HIGH', 'LOW')

        Data:
        {"tags": ["critical", "open"]}

        Output:
        "HIGH"
        """
        return if_true if test else if_false

    @functions.signature({'types': []})
    def _func_type(self, value: Any) -> str:  # noqa: PLR0911
        """Return the JMESPath type name of a value.

        Expression:
        type(field)

        Data:
        {"field": [1, 2, 3]}

        Output:
        "ARRAY"
        """
        match value:
            case bool():  # must precede int since bool subclasses int
                return 'BOOLEAN'
            case None:
                return 'NULL'
            case dict():
                return 'OBJECT'
            case list():
                return 'ARRAY'
            case int() | float():
                return 'NUMBER'
            case str():
                return 'STRING'
            case _:
                return 'UNKNOWN'
