"""Custom functions for ThreatConnect Jmespath Playbook App."""

import collections

import jmespath
from jmespath import exceptions, functions

from .jmespath_functions_array_mixin import ArrayFunctionsMixin
from .jmespath_functions_control_mixin import ControlFunctionsMixin
from .jmespath_functions_crypto_mixin import CryptoFunctionsMixin
from .jmespath_functions_datetime_mixin import DateTimeFunctionsMixin
from .jmespath_functions_math_mixin import MathFunctionsMixin
from .jmespath_functions_object_mixin import ObjectFunctionsMixin
from .jmespath_functions_string_mixin import StringFunctionsMixin


def jmespath_options() -> jmespath.Options:
    """Return the jmespath options."""
    return jmespath.Options(custom_functions=TcFunctions(), dict_cls=collections.OrderedDict)


class TcFunctions(
    ArrayFunctionsMixin,
    ControlFunctionsMixin,
    CryptoFunctionsMixin,
    DateTimeFunctionsMixin,
    MathFunctionsMixin,
    ObjectFunctionsMixin,
    StringFunctionsMixin,
    functions.Functions,
):
    """ThreatConnect custom jmespath functions."""

    def _type_check(self, actual: list, signature: tuple, function_name: str):
        """Check the arg type to signature type."""
        for i in range(min(len(signature), len(actual))):
            allowed_types = signature[i]['types']
            if allowed_types:
                self._type_check_single(actual[i], allowed_types, function_name)

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
