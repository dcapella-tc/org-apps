"""Custom functions for ThreatConnect Jmespath Playbook App."""

# standard library
import collections
import itertools
import uuid
from copy import deepcopy
from typing import Any

# third-party
import jmespath
from jmespath import exceptions, functions
from jmespath.visitor import _Expression

from ..util import Util


def jmespath_options() -> jmespath.Options:
    """Return the jmespath options."""
    return jmespath.Options(custom_functions=TcFunctions(), dict_cls=collections.OrderedDict)


class TcFunctions(functions.Functions):
    """ThreatConnect custom jmespath functions."""

    def _get_expression_key(self, expref: _Expression):
        """Return the key from the expression."""
        match expref.expression['type']:  # type: ignore
            case 'field':
                return expref.expression['value']  # type: ignore

            case 'subexpression':
                return expref.expression.get('children')[-1]['value']  # type: ignore

            case _:
                ex_msg = f"""Invalid expression type of {expref.expression['type']}."""  # type: ignore

                raise RuntimeError(ex_msg)

    def _update_expression_parent(self, expref: _Expression, key: str, item: dict, value: Any):
        """Return the key from the expression."""
        match expref.expression['type']:  # type: ignore
            case 'field':
                item[key] = value

            case 'subexpression':
                expand_item = item
                children = expref.expression.get('children') or []  # type: ignore

                for index, child in enumerate(children):
                    child_value = child['value']
                    expand_item = expand_item[child_value]

                    if index == len(children) - 2:
                        expand_item[key] = value

    @functions.signature({'types': ['string']}, {'types': ['string']})
    def _func_format_datetime(self, input_: str, date_format: str):
        """Return array after popping value at address out.

        Expression:
        {
            group: [].{
                name: 'post_title',
                type: 'Event',
                eventDate: format_datetime(discovered, '%Y-%m-%dT%H:%M:%SZ')
            }
        }
        """
        return Util.any_to_datetime(input_).strftime(date_format)

    @functions.signature({'types': ['array']}, {'types': ['expref']})
    def _func_expand(self, array: list[dict], expref: _Expression):
        """Expand results into an array of objects.

        Expression:
        expand(@, &urls)

        Data:
        [
            {
                "id": "123",
                "urls": [
                    "abc.example.com",
                    "def.example.com"
                ],
                "category": "Malicious"
            }
        ]

        Output:
        [
            {
                "id": "123",
                "urls": "abc.example.com",
                "category": "Malicious"
            },
            {
                "id": "123",
                "urls": "def.example.com",
                "category": "Malicious"
            }
        ]
        """
        # short circuit, if no array
        if not array:
            return array

        key_func = self._create_key_func(expref, ['array'], 'expand2')  # type: ignore

        expression_key = self._get_expression_key(expref)

        result = []
        for item in array:
            for key in key_func(item):
                new_item = deepcopy(item)
                self._update_expression_parent(expref, expression_key, new_item, key)
                result.append(new_item)
        return result

    @functions.signature({'types': ['array']}, {'types': ['expref']})
    def _func_group_by(self, array: list[dict], expref: _Expression):
        """Group results into an array of objects.

        Expression:
        group_by(items, &spec.nodeName)

        Data:
        {
          "items": [
            {
              "spec": {
                "nodeName": "node_01",
                "other": "values_01"
              }
            },
            {
              "spec": {
                "nodeName": "node_02",
                "other": "values_02"
              }
            },
            {
              "spec": {
                "nodeName": "node_01",
                "other": "values_04"
              }
            }
          ]
        }

        Output:
        {
            "node_01": [
                {
                    "spec": {
                        "nodeName": "node_01",
                        "other": "values_01"
                    }
                },
                {
                    "spec": {
                        "nodeName": "node_01",
                        "other": "values_04"
                    }
                }
            ],
            "node_02": [
                {
                    "spec": {
                        "nodeName": "node_02",
                        "other": "values_02"
                    }
                }
            ]
        }
        """
        # short circuit, if no array
        if not array:
            return array

        key_func = self._create_key_func(expref, ['null', 'string'], 'group_by')  # type: ignore

        result = {}
        for item in array:
            result.setdefault(key_func(item), []).append(item)
        return result

    @functions.signature({'types': ['array']}, {'types': ['string']})
    def _func_delete(self, arr: list, search: str):
        """Return array of objects after removing key for each object.

        Expression:
        delete([], 'state')
        """
        for a in arr:
            a.pop(search, None)
        return arr

    @functions.signature({'types': ['array']}, {'types': ['string']})
    def _func_null_leaf(self, arr: list, search: str):
        """Return value in array even if they are null.

        Expression:
        locations[] | null_leaf(@, 'state')
        """
        return [a.get(search) for a in arr]

    @functions.signature({'types': ['string']}, {'types': ['string']}, {'types': ['string']})
    def _func_replace(self, input_: str, search: str, replace: str, count: int = -1):
        """Replace occurrences of search with replace in the input string.

        Expression:
        replace('hello world', 'world', 'there')

        Output:
        'hello there'
        """
        return input_.replace(search, replace, count)

    @functions.signature({'types': ['string']})
    def _func_uuid5(self, input_: str):
        """Return array after popping value at address out.

        Expression:
        {
            group: [].{
                name: 'post_title',
                type: 'Event',
                eventDate: format_datetime(discovered, '%Y-%m-%dT%H:%M:%SZ')
                xid: uuid5(post_title)
            }
        }
        """
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, input_))

    @functions.signature(
        {'types': ['array']},
        {'types': ['null', 'string'], 'optional': True},  # type: ignore
    )
    def _func_zip(self, arrays: list[list], fill_value: str | None = None):
        """Return array after popping value at address out.

        Expression:
        {data: zip([first_names, last_names, ages])}

        Data:
        {
            "first_names": ["bob", "joe", "sally"],
            "last_names": ["smith", "jones", "blah"]
            "ages": ["32", "41"]
        }

        Output
        {
            data: [
                [bob, smith, 32],
                [joe, jones, 41],
                [sally, blah, null]
            ]
        }
        """
        return list(itertools.zip_longest(*arrays, fillvalue=fill_value))

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['null', 'string'], 'optional': True},  # type: ignore
    )
    def _func_zip_to_objects(
        self,
        keys: list[str],
        values: list[list],
        fill_value: str | None = None,
    ):
        """Return array after popping value at address out.

        Expression:
        {data: zip_to_object(['name', 'last_name', 'age'], [first_names, last_names, ages]}

        Data:
        {
            "first_names": ["bob", "joe", "sally"],
            "last_names": ["smith", "jones", "blah"]
            "ages": ["30", "40"]
        }

        Output:
        {
            data: [
                {
                    first_name: bob,
                    last_name: smith,
                    age: 30
                },
                {
                    first_name: joe,
                    last_name: jones,
                    age: 40
                },
                {
                    first_name: sally,
                    last_name: blah,
                    age: null
                }
            ]
        }
        """
        if len(keys) != len(values):
            ex_msg = 'Keys and values must be the same length.'
            raise RuntimeError(ex_msg)

        data = []
        values = itertools.zip_longest(*values, fillvalue=fill_value)  # type: ignore
        for value in values:
            data.append({k: value[i] for i, k in enumerate(keys)})
        return data

    #
    # Update jmespath Functions plumbing to support optional inputs
    #

    def _type_check(self, actual: list, signature: tuple, function_name: str):
        """Check the arg type to signature type."""
        for i in range(min(len(signature), len(actual))):
            allowed_types = signature[i]['types']
            if allowed_types:
                self._type_check_single(actual[i], allowed_types, function_name)  # type: ignore

    def _validate_arguments(self, args: list, signature: tuple, function_name: str):
        """Check the provided args match the signature type, taking into account optional args."""
        # short circuit, if no signature
        if len(signature) == 0:
            return self._type_check(args, signature, function_name)

        # get the number of required and optional arguments
        required_arguments_count = len(
            [param for param in signature if param.get('optional', False) is not True]
        )
        optional_arguments_count = len(
            [param for param in signature if param.get('optional', False) is not True]
        )
        has_variadic = signature[-1].get('variadic', False)

        if has_variadic:
            if len(args) < len(signature):
                raise exceptions.VariadictArityError(len(signature), len(args), function_name)
        elif optional_arguments_count > 0:
            if len(args) < required_arguments_count or len(args) > (
                required_arguments_count + optional_arguments_count
            ):
                raise exceptions.ArityError(len(signature), len(args), function_name)
        elif len(args) != required_arguments_count:
            raise exceptions.ArityError(len(signature), len(args), function_name)
        return self._type_check(args, signature, function_name)
