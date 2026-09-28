"""Array manipulation functions for ThreatConnect JMESPath custom functions."""

import itertools
import json
from copy import deepcopy
from typing import Any

from jmespath import functions
from jmespath.visitor import _Expression

from .jmespath_functions_base import JmespathFunctionsBase


class ArrayFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing array manipulation JMESPath functions.

    Functions: array_join, cartesian, chunk, compact, dedup, delete, difference,
    expand, fill, flatten_list, group_adjacent, group_by, index_array,
    intersect, null_leaf, symmetric_difference, union, zip, zip_merge, zip_to_objects.
    """

    @functions.signature({'types': ['array', 'string']}, {'types': [], 'variadic': True})
    def _func_array_join(self, *args) -> list:
        """Append items to the end of an array or string input.

        When the first argument is a string it is wrapped in a list before processing.
        Each subsequent item is extended into the result when it is itself an array,
        or appended as a single element when it is a string or any other scalar.

        Expression:
        array_join(items, 'new_item')

        Data:
        {"items": [1, 2, 3]}

        Output:
        [1, 2, 3, "new_item"]
        """
        first = args[0]
        result = list(first) if isinstance(first, list) else [first]
        for item in args[1:]:
            if isinstance(item, list):
                result.extend(item)
            else:
                result.append(item)
        return result

    @functions.signature({'types': ['array']})
    def _func_cartesian(self, lists: list[list]) -> list:
        """Create the cartesian product of multiple arrays.

        Expression:
        cartesian([colors, sizes])

        Data:
        {"colors": ["red", "blue"], "sizes": ["S", "M"]}

        Output:
        [["red", "S"], ["red", "M"], ["blue", "S"], ["blue", "M"]]
        """
        return [list(combo) for combo in itertools.product(*lists)]

    @functions.signature({'types': ['array']}, {'types': ['number']})
    def _func_chunk(self, lst: list, size: int) -> list[list]:
        """Chunk an array into smaller arrays of the given size.

        Expression:
        chunk(items, `2`)

        Data:
        {"items": [1, 2, 3, 4, 5]}

        Output:
        [[1, 2], [3, 4], [5]]
        """
        n = int(size)
        if n < 1:
            ex_msg = 'n must be at least one'
            raise ValueError(ex_msg)
        return [lst[i : i + n] for i in range(0, len(lst), n)]

    @functions.signature({'types': ['array']})
    def _func_compact(self, array: list) -> list:
        """Remove all null values from an array.

        Expression:
        compact(items)

        Data:
        {"items": [1, null, 2, null, 3]}

        Output:
        [1, 2, 3]
        """
        return [item for item in array if item is not None]

    @functions.signature({'types': ['array']})
    def _func_dedup(self, array: list) -> list:
        """Remove duplicate items from an array based on token equality.

        Order is preserved; only the first occurrence of each token is kept.

        Expression:
        dedup(tags)

        Data:
        {"tags": ["a", "b", "a", "c", "b"]}

        Output:
        ["a", "b", "c"]
        """
        seen = set()
        result = []
        for item in array:
            token = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
            if token not in seen:
                seen.add(token)
                result.append(item)
        return result

    @functions.signature({'types': ['array']}, {'types': ['string'], 'variadic': True})
    def _func_delete(self, arr: list, *searches: str) -> list:
        """Remove keys or matching values from an array, accepting one or more search terms.

        When the array contains objects, each search term is removed as a key from every object.
        When the array contains strings, every element matching any search term is removed.

        Expression (array of objects):
        delete(locations, 'state')

        Data:
        {"locations": [{"city": "Austin", "state": "TX"}, {"city": "Denver", "state": "CO"}]}

        Output:
        [{"city": "Austin"}, {"city": "Denver"}]

        Expression (array of strings, multiple terms):
        delete(tags, 'TX', 'CO')

        Data:
        {"tags": ["TX", "CO", "CA"]}

        Output:
        ["CA"]
        """
        if arr and isinstance(arr[0], dict):
            for a in arr:
                for search in searches:
                    a.pop(search, None)
            return arr
        remove = set(searches)
        return [a for a in arr if a not in remove]

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['boolean', 'null'], 'optional': True},
    )
    def _func_difference(
        self, left: list, right: list, preserve_order: bool | None = False
    ) -> list:
        """Return elements in left that are not in right.

        When preserve_order is true, the result follows the order of left
        and duplicates are excluded. When preserve_order is false (default), Python set
        difference is used — faster but unordered.

        Expression:
        difference(a, b)
        difference(a, b, `false`)   # unordered, uses set difference

        Data:
        {"a": [1, 2, 3, 4], "b": [2, 4, 6]}

        Output:
        [1, 3]
        """
        if preserve_order is False:
            return list(set(left).difference(right))
        right_set = set(right)
        seen: set = set()
        result = []
        for item in left:
            if item not in right_set and item not in seen:
                seen.add(item)
                result.append(item)
        return result

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

    @functions.signature({'types': ['array']}, {'types': ['number']}, {'types': []})
    def _func_fill(self, array: list, count: int, default: Any) -> list:
        """Take the first N elements from an array, padding with a default value if needed.

        Expression:
        fill(items, `5`, 'n/a')

        Data:
        {"items": ["a", "b"]}

        Output:
        ["a", "b", "n/a", "n/a", "n/a"]
        """
        n = int(count)
        result = list(array[:n])
        while len(result) < n:
            result.append(default)
        return result

    @functions.signature({'types': ['array']})
    def _func_flatten_list(self, array: list) -> list:
        """Flatten a nested list into a single flat list.

        Expression:
        flatten_list(nested)

        Data:
        {"nested": [1, [2, 3], [4, [5, 6]]]}

        Output:
        [1, 2, 3, 4, 5, 6]
        """
        result = []
        for item in array:
            if isinstance(item, list):
                result.extend(self._func_flatten_list(item))
            else:
                result.append(item)
        return result

    @functions.signature({'types': ['array']}, {'types': ['expref']})
    def _func_group_adjacent(self, array: list, expref: _Expression) -> list:
        """Group consecutive elements that share the same key into sub-arrays.

        Unlike group_by, only adjacent elements with a matching key are grouped.
        Non-adjacent elements with the same key form separate groups.

        Expression:
        group_adjacent(items, &category)

        Data:
        {"items": [{"category": "a", "v": 1}, {"category": "a", "v": 2}, {"category": "b", "v": 3}]}

        Output:
        [[{"category": "a", "v": 1}, {"category": "a", "v": 2}], [{"category": "b", "v": 3}]]
        """
        key_func = self._create_key_func(expref, ['null', 'string', 'number'], 'group_adjacent')  # type: ignore
        result = []
        for _, group in itertools.groupby(array, key=key_func):
            result.append(list(group))
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

    @functions.signature(
        {'types': ['array']},
        {'types': ['string']},
        {'types': ['number', 'null'], 'optional': True},
    )
    def _func_index_array(
        self, lst: list[dict], field: str, start: int | None = None
    ) -> list[dict]:
        """Add a sequential index field to each object in an array.

        Expression:
        index_array(items, 'idx', `1`)

        Data:
        {"items": [{"name": "a"}, {"name": "b"}]}

        Output:
        [{"name": "a", "idx": 1}, {"name": "b", "idx": 2}]
        """
        start_idx = int(start) if start is not None else 0
        result = []
        for i, item in enumerate(lst):
            new_item = deepcopy(item)
            new_item[field] = start_idx + i
            result.append(new_item)
        return result

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['boolean', 'null'], 'optional': True},
    )
    def _func_intersect(self, left: list, right: list, preserve_order: bool | None = False) -> list:
        """Return elements common to both arrays with optional order preservation.

        When preserve_order is true, the result follows the order of left
        and duplicates are excluded. When preserve_order is false (default), Python set
        intersection is used — faster but unordered.

        Expression:
        intersect(a, b)
        intersect(a, b, `true`)   # preserve order
        intersect(a, b, `false`)  # unordered, uses set intersection

        Data:
        {"a": [1, 2, 3, 4], "b": [2, 4, 6]}

        Output:
        [2, 4]
        """
        if preserve_order is False:
            return list(set(left).intersection(right))
        right_set = set(right)
        seen: set = set()
        result = []
        for item in left:
            if item in right_set and item not in seen:
                seen.add(item)
                result.append(item)
        return result

    # TODO: list_join commented out for further review before next release
    # @functions.signature(
    #     {'types': ['array']},
    #     {'types': ['array']},
    #     {'types': ['expref']},
    #     {'types': ['expref']},
    # )
    # def _func_list_join(
    #     self,
    #     left: list,
    #     right: list,
    #     left_expref: _Expression,
    #     right_expref: _Expression,
    # ) -> list:
    #     """Perform a full outer join of two arrays matched by key expressions.
    #
    #     Returns an array of objects, each with __index, left (matching items
    #     from the first array), and right (matching items from the second array).
    #     Entries without a counterpart on either side are included with an
    #     empty array for the unmatched side.
    #
    #     Expression:
    #     list_join(people, teams, &teamId, &id)
    #     """
    #     left_key_func = self._create_key_func(
    #         left_expref, ['null', 'string', 'number'], 'list_join'
    #     )
    #     right_key_func = self._create_key_func(
    #         right_expref, ['null', 'string', 'number'], 'list_join'
    #     )
    #
    #     left_groups: dict = {}
    #     for item in left:
    #         if item is None:
    #             continue
    #         left_groups.setdefault(left_key_func(item), []).append(item)
    #
    #     right_groups: dict = {}
    #     for item in right:
    #         if item is None:
    #             continue
    #         right_groups.setdefault(right_key_func(item), []).append(item)
    #
    #     all_keys: list = list(left_groups.keys())
    #     for key in right_groups:
    #         if key not in all_keys:
    #             all_keys.append(key)
    #
    #     return [
    #         {
    #             '__index': idx,
    #             'left': left_groups.get(key, []),
    #             'right': right_groups.get(key, []),
    #         }
    #         for idx, key in enumerate(all_keys)
    #     ]

    @functions.signature({'types': ['array']}, {'types': ['string']})
    def _func_null_leaf(self, arr: list, search: str) -> list:
        """Extract a key from every object in an array, preserving null values.

        Unlike a standard JMESPath projection, missing keys are returned as
        null rather than being dropped from the result.

        Expression:
        null_leaf(locations, 'state')

        Data:
        {"locations": [{"city": "Austin", "state": "TX"}, {"city": "Denver"}]}

        Output:
        ["TX", null]
        """
        return [a.get(search) for a in arr]

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['boolean', 'null'], 'optional': True},
    )
    def _func_symmetric_difference(
        self, left: list, right: list, preserve_order: bool | None = False
    ) -> list:
        """Return elements in either array but not in both.

        When preserve_order is true, left-only elements appear first
        (in left order) followed by right-only elements (in right order), with
        duplicates excluded. When preserve_order is false (default), Python set symmetric
        difference is used — faster but unordered.

        Expression:
        symmetric_difference(a, b)
        symmetric_difference(a, b, `false`)   # unordered, uses set symmetric difference

        Data:
        {"a": [1, 2, 3, 4], "b": [2, 4, 6]}

        Output:
        [1, 3, 6]
        """
        if preserve_order is False:
            return list(set(left).symmetric_difference(right))
        left_set = set(left)
        right_set = set(right)
        seen: set = set()
        result = []
        for item in left:
            if item not in right_set and item not in seen:
                seen.add(item)
                result.append(item)
        for item in right:
            if item not in left_set and item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['boolean', 'null'], 'optional': True},
    )
    def _func_union(self, left: list, right: list, preserve_order: bool | None = False) -> list:
        """Return all unique elements from both arrays.

        When preserve_order is true, left elements appear first
        (in left order) followed by right-only elements (in right order), with
        duplicates excluded. When preserve_order is false (default), Python set union
        is used — faster but unordered.

        Expression:
        union(a, b)
        union(a, b, `false`)   # unordered, uses set union

        Data:
        {"a": [1, 2, 3], "b": [2, 3, 4]}

        Output:
        [1, 2, 3, 4]
        """
        if preserve_order is False:
            return list(set(left).union(right))
        seen: set = set()
        result = []
        for item in left + right:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @functions.signature(
        {'types': ['array']},
        {'types': ['null', 'string'], 'optional': True},
    )
    def _func_zip(self, arrays: list[list], fill_value: str | None = None) -> list[tuple]:
        """Transpose an array of arrays into a list of tuples, padding short arrays with fill_value.

        Expression:
        zip([first_names, last_names, ages])

        Data:
        {
            "first_names": ["bob", "joe", "sally"],
            "last_names": ["smith", "jones", "blah"],
            "ages": ["32", "41"]
        }

        Output:
        [
            ["bob", "smith", "32"],
            ["joe", "jones", "41"],
            ["sally", "blah", null]
        ]
        """
        return list(itertools.zip_longest(*arrays, fillvalue=fill_value))

    @functions.signature({'types': ['array']}, {'types': ['array']})
    def _func_zip_merge(self, left: list[dict], right: list[dict]) -> list[dict]:
        """Merge two arrays of objects by position, combining keys from each pair.

        Pairs each object at the same index from both arrays and spreads their
        keys into a single object. Truncates at the shorter array.

        Expression:
        zip_merge(names, ages)

        Data:
        {"names": [{"name": "Alice"}, {"name": "Bob"}], "ages": [{"age": 30}, {"age": 25}]}

        Output:
        [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]
        """
        return [
            {**left_item, **right_item} for left_item, right_item in zip(left, right, strict=False)
        ]

    @functions.signature(
        {'types': ['array']},
        {'types': ['array']},
        {'types': ['null', 'string'], 'optional': True},
    )
    def _func_zip_to_objects(
        self,
        keys: list[str],
        values: list[list],
        fill_value: str | None = None,
    ) -> list[dict]:
        """Zip parallel arrays into a list of objects using the provided keys.

        Each positional element across all value arrays becomes one object.
        Shorter arrays are padded with fill_value (default: null).

        Expression:
        zip_to_objects(['first_name', 'last_name', 'age'], [first_names, last_names, ages])

        Data:
        {
            "first_names": ["bob", "joe", "sally"],
            "last_names": ["smith", "jones", "blah"],
            "ages": ["30", "40"]
        }

        Output:
        [
            {"first_name": "bob", "last_name": "smith", "age": "30"},
            {"first_name": "joe", "last_name": "jones", "age": "40"},
            {"first_name": "sally", "last_name": "blah", "age": null}
        ]
        """
        if len(keys) != len(values):
            ex_msg = 'Keys and values must be the same length.'
            raise RuntimeError(ex_msg)

        data = []
        values = itertools.zip_longest(*values, fillvalue=fill_value)  # type: ignore
        for value in values:
            data.append({k: value[i] for i, k in enumerate(keys)})
        return data
