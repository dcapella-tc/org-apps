"""Math functions for ThreatConnect JMESPath custom functions."""

import math
import random
from typing import Any

from jmespath import functions

from .jmespath_functions_base import JmespathFunctionsBase


class MathFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing math JMESPath functions.

    Functions: add, divide, mod, multiply, power, rand, subtract, to_int.
    """

    @functions.signature({'types': ['number', 'array'], 'variadic': True})
    def _func_add(self, *args) -> float:
        """Sum any number of scalar values or an array of numbers.

        Expression (two values):
        add(a, b)

        Data:
        {"a": 3, "b": 4}

        Output:
        7

        Expression (multiple):
        add(a, b, c)

        Data:
        {"a": 1, "b": 2, "c": 3}

        Output:
        6

        Expression (array):
        add(amounts)

        Data:
        {"amounts": [1, 2, 3]}

        Output:
        6
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        return sum(values)

    @functions.signature({'types': ['number']}, {'types': ['number']})
    def _func_divide(self, dividend: float, divisor: float) -> float | None:
        """Divide two numbers, returning null on division by zero.

        Expression:
        divide(a, b)

        Data:
        {"a": 10, "b": 4}

        Output:
        2.5
        """
        if divisor == 0:
            return None
        return dividend / divisor

    @functions.signature({'types': ['number']}, {'types': ['number']})
    def _func_mod(self, value: float, base: float) -> float:
        """Return the modulo of value divided by base.

        Expression:
        mod(a, b)

        Data:
        {"a": 7, "b": 3}

        Output:
        1
        """
        return value % base

    @functions.signature({'types': ['number', 'array'], 'variadic': True})
    def _func_multiply(self, *args) -> float:
        """Multiply any number of scalar values or an array of numbers together.

        Expression (two values):
        multiply(a, b)

        Data:
        {"a": 3.0, "b": 4.0}

        Output:
        12.0

        Expression (multiple):
        multiply(a, b, c)

        Data:
        {"a": 2, "b": 3, "c": 4}

        Output:
        24

        Expression (array):
        multiply(factors)

        Data:
        {"factors": [2, 3, 4]}

        Output:
        24
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        return math.prod(values)

    @functions.signature({'types': ['number']}, {'types': ['number']})
    def _func_power(self, value: float, exponent: float) -> float:
        """Raise value to the given exponent.

        Expression:
        power(a, b)

        Data:
        {"a": 2, "b": 3}

        Output:
        8
        """
        return value**exponent

    @functions.signature({'types': ['number']}, {'types': ['number']})
    def _func_rand_int(self, min_: int, max_: int) -> int:
        """Return a random integer between min and max (inclusive).

        Expression:
        rand_int(mn, mx)

        Data:
        {"mn": 1, "mx": 100}

        Output:
        42
        """
        return random.randint(int(min_), int(max_))

    @functions.signature({'types': ['number', 'array'], 'variadic': True})
    def _func_subtract(self, *args) -> float:
        """Subtract all subsequent values from the first.

        Expression (two values):
        subtract(a, b)

        Data:
        {"a": 100, "b": 15}

        Output:
        85

        Expression (multiple):
        subtract(a, b, c)

        Data:
        {"a": 100, "b": 15, "c": 5}

        Output:
        80

        Expression (array):
        subtract(amounts)

        Data:
        {"amounts": [100, 15, 5]}

        Output:
        80
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        return values[0] - sum(values[1:])

    @functions.signature({'types': ['number', 'array'], 'variadic': True})
    def _func_to_int(self, *args) -> int | list[int]:
        """Convert one or more numbers to integers by truncating towards zero.

        Expression (number):
        to_int(score)

        Data:
        {"score": 9.9}

        Output:
        9

        Expression (multiple):
        to_int(a, b)

        Data:
        {"a": 9.9, "b": -3.7}

        Output:
        [9, -3]

        Expression (array):
        to_int(scores)

        Data:
        {"scores": [9.9, -3.7, 5]}

        Output:
        [9, -3, 5]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1:
            return int(values[0])
        return [int(item) for item in values]
