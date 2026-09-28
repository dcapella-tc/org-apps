"""Object manipulation functions for ThreatConnect JMESPath custom functions."""

import json
from copy import deepcopy
from typing import Any

import yaml
from jmespath import functions

from .jmespath_functions_base import JmespathFunctionsBase


class ObjectFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing object manipulation JMESPath functions.

    Functions: exclude_keys, exclude_values, include_keys, json_parse, json_stringify, merge,
    to_key_value_array, yaml_parse.
    """

    @functions.signature({'types': ['object']}, {'types': ['string'], 'variadic': True})
    def _func_exclude_keys(self, obj: dict, *keys: str) -> dict:
        """Remove one or more keys from an object.

        Expression (single key):
        exclude_keys(@, 'password')

        Data:
        {"name": "John", "password": "abc"}

        Output:
        {"name": "John"}

        Expression (multiple keys):
        exclude_keys(@, 'password', 'secret')

        Data:
        {"name": "John", "password": "abc", "secret": "xyz"}

        Output:
        {"name": "John"}
        """
        remove = set(keys)
        return {k: v for k, v in obj.items() if k not in remove}

    @functions.signature({'types': ['object']}, {'types': [], 'variadic': True})
    def _func_exclude_values(self, obj: dict, *values) -> dict:
        """Recursively remove entries from an object whose values match any of the given sentinels.

        Expression (single sentinel):
        exclude_values(@, `null`)

        Data:
        {"name": "John", "age": null}

        Output:
        {"name": "John"}

        Expression (multiple sentinels):
        exclude_values(@, `null`, `''`, `0`)

        Data:
        {"name": "John", "age": null, "score": 0, "city": ""}

        Output:
        {"name": "John"}
        """

        def _strip(value: Any) -> Any:
            if isinstance(value, dict):
                return {k: _strip(v) for k, v in value.items() if v not in values}
            return value

        return _strip(obj)

    @functions.signature({'types': ['object']}, {'types': ['string'], 'variadic': True})
    def _func_include_keys(self, obj: dict, *keys: str) -> dict:
        """Keep only the specified keys in an object, discarding all others.

        Expression (single key):
        include_keys(@, 'name')

        Data:
        {"name": "John", "age": 30, "city": "NY"}

        Output:
        {"name": "John"}

        Expression (multiple keys):
        include_keys(@, 'name', 'age')

        Data:
        {"name": "John", "age": 30, "city": "NY"}

        Output:
        {"name": "John", "age": 30}
        """
        keep = set(keys)
        return {k: v for k, v in obj.items() if k in keep}

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_json_parse(self, *args) -> Any:
        r"""Parse one or more JSON strings into native objects.

        Returns the parsed object when given a single string, or a list of
        parsed objects when given multiple strings or an array of strings.

        Expression (string):
        json_parse(raw)

        Data:
        {"raw": "{\"greeting\": \"hello world!\"}"}

        Output:
        {"greeting": "hello world!"}

        Expression (multiple):
        json_parse(a, b)

        Data:
        {"a": "{\"x\": 1}", "b": "{\"y\": 2}"}

        Output:
        [{"x": 1}, {"y": 2}]

        Expression (array):
        json_parse(raws)

        Data:
        {"raws": ["{\"x\": 1}", "{\"y\": 2}"]}

        Output:
        [{"x": 1}, {"y": 2}]
        """
        values = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return json.loads(values[0])
        return [json.loads(item) if isinstance(item, str) else item for item in values]

    @functions.signature({'types': []})
    def _func_json_stringify(self, value: Any) -> str:
        r"""Serialize a value to a JSON string.

        Expression:
        json_stringify(payload)

        Data:
        {"payload": {"greeting": "hello world!"}}

        Output:
        "{\"greeting\": \"hello world!\"}"
        """
        return json.dumps(value)

    @functions.signature({'types': ['object']}, {'types': ['object'], 'variadic': True})
    def _func_merge(self, *args: dict) -> dict:
        """Merge two or more objects, concatenating array values and replacing scalar values.

        Array values at the same key are concatenated rather than replaced,
        and nested objects are merged recursively.

        Expression:
        merge(base, overrides)

        Data:
        {"base": {"roles": ["user"], "active": false},
         "overrides": {"roles": ["admin"], "active": true}}

        Output:
        {"roles": ["user", "admin"], "active": true}
        """

        def _merge_two(base: dict, other: dict) -> dict:
            result = deepcopy(base)
            for key, value in other.items():
                if key in result:
                    if isinstance(result[key], list) and isinstance(value, list):
                        result[key] = result[key] + value
                    elif isinstance(result[key], dict) and isinstance(value, dict):
                        result[key] = _merge_two(result[key], value)
                    else:
                        result[key] = deepcopy(value)
                else:
                    result[key] = deepcopy(value)
            return result

        result = args[0] if args else {}
        for other in args[1:]:
            result = _merge_two(result, other)
        return result

    @functions.signature({'types': ['object']})
    def _func_to_key_value_array(self, obj: dict) -> list[dict]:
        """Convert an object into an array of key-value pair objects.

        Expression:
        to_key_value_array(@)

        Data:
        {"name": "John", "age": 30}

        Output:
        [{"key": "name", "value": "John"}, {"key": "age", "value": 30}]
        """
        return [{'key': k, 'value': v} for k, v in obj.items()]

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_yaml_parse(self, *args) -> Any:
        r"""Parse one or more YAML-encoded strings into native objects for further traversal.

        Returns the parsed object when given a single string, or a list of
        parsed objects when given multiple strings or an array of strings.

        Expression (string):
        yaml_parse(config) | server.port

        Data:
        {"config": "server:\n  port: 8080\n  host: localhost"}

        Output:
        8080

        Expression (multiple):
        yaml_parse(a, b)

        Data:
        {"a": "key: value", "b": "num: 42"}

        Output:
        [{"key": "value"}, {"num": 42}]

        Expression (array):
        yaml_parse(configs)

        Data:
        {"configs": ["key: value", "num: 42"]}

        Output:
        [{"key": "value"}, {"num": 42}]
        """
        values = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return yaml.safe_load(values[0])
        return [yaml.safe_load(item) if isinstance(item, str) else item for item in values]
