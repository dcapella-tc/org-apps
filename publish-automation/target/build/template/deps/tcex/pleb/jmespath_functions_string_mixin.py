"""String manipulation functions for ThreatConnect JMESPath custom functions."""

import base64
import fnmatch
import json
import re
import urllib.parse
from typing import Any

from jmespath import functions

from ..util import Util
from .jmespath_functions_base import JmespathFunctionsBase


class StringFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing string manipulation JMESPath functions.

    Functions: base64_decode, base64_encode, capitalize, decode_url, defang, encode_url, equal_fold,
    lower, pattern_match, refang, regex, regex_match, regex_replace, replace, split,
    string_interpolate, trim, upper.
    """

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_base64_decode(self, *args) -> str | list[str]:
        """Decode one or more base64 (RFC 4648) encoded strings, or each string in an array.

        Expression (string):
        base64_decode(encoded_field)

        Data:
        {"encoded_field": "SGVsbG8gV29ybGQh"}

        Output:
        "Hello World!"

        Expression (multiple):
        base64_decode(a, b)

        Data:
        {"a": "SGVsbG8gV29ybGQh", "b": "Zm9v"}

        Output:
        ["Hello World!", "foo"]

        Expression (array):
        base64_decode(encoded_fields)

        Data:
        {"encoded_fields": ["SGVsbG8gV29ybGQh", "Zm9v"]}

        Output:
        ["Hello World!", "foo"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return base64.b64decode(values[0]).decode('utf-8')
        return [
            base64.b64decode(item).decode('utf-8') if isinstance(item, str) else item
            for item in values
        ]

    @functions.signature({'types': ['string', 'array']})
    def _func_base64_encode(self, value: str | list | dict) -> str:
        """Encode a value to Base64 (RFC 4648).

        Strings are encoded directly; other types are JSON-serialized first.

        Expression (string):
        base64_encode(message)

        Data:
        {"message": "Hello World!"}

        Output:
        "SGVsbG8gV29ybGQh"

        Expression (object):
        base64_encode(payload)

        Data:
        {"payload": {"key": "val"}}

        Output:
        "eyJrZXkiOiAidmFsIn0="
        """
        raw = value.encode('utf-8') if isinstance(value, str) else json.dumps(value).encode('utf-8')
        return base64.b64encode(raw).decode('utf-8')

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_capitalize(self, *args) -> str | list[str]:
        """Capitalize all words in a string, multiple strings, or an array of strings.

        Expression (string):
        capitalize(name)

        Data:
        {"name": "john doe"}

        Output:
        "John Doe"

        Expression (multiple):
        capitalize(first, last)

        Data:
        {"first": "john", "last": "doe"}

        Output:
        ["John", "Doe"]

        Expression (array):
        capitalize(names)

        Data:
        {"names": ["john doe", "jane smith"]}

        Output:
        ["John Doe", "Jane Smith"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return values[0].title()
        return [item.title() if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_decode_url(self, *args) -> str | list[str]:
        """Decode one or more percent-encoded (URL-encoded) strings.

        Expression (string):
        decode_url(encoded)

        Data:
        {"encoded": "hello%20world%21"}

        Output:
        "hello world!"

        Expression (multiple):
        decode_url(url1, url2)

        Data:
        {"url1": "hello%20world", "url2": "foo%21bar"}

        Output:
        ["hello world", "foo!bar"]

        Expression (array):
        decode_url(encoded_urls)

        Data:
        {"encoded_urls": ["hello%20world", "foo%21bar"]}

        Output:
        ["hello world", "foo!bar"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return urllib.parse.unquote(values[0])
        return [urllib.parse.unquote(item) if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_defang(self, *args) -> str | list[str]:
        """Defang one or more URLs, IPs, domains, or emails to make them inert.

        Applies the following replacements: http:// → hxxp://, https:// → hxxps://,
        ftp:// → fxp://, . → [.], : → [:], @ → [@].

        Expression (string):
        defang(indicator)

        Data:
        {"indicator": "https://malicious.example.com"}

        Output:
        "hxxps[:]//malicious[.]example[.]com"

        Expression (multiple):
        defang(url, ip)

        Data:
        {"url": "https://evil.com", "ip": "192.168.1.1"}

        Output:
        ["hxxps[:]//evil[.]com", "192[.]168[.]1[.]1"]

        Expression (array):
        defang(indicators)

        Data:
        {"indicators": ["https://malicious.example.com", "192.168.1.1"]}

        Output:
        ["hxxps[:]//malicious[.]example[.]com", "192[.]168[.]1[.]1"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return Util.defang(values[0])
        return [Util.defang(item) if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_encode_url(self, *args) -> str | list[str]:
        """Percent-encode (URL-encode) one or more strings, encoding all special characters.

        Expression (string):
        encode_url(path)

        Data:
        {"path": "hello world!"}

        Output:
        "hello%20world%21"

        Expression (multiple):
        encode_url(path1, path2)

        Data:
        {"path1": "hello world", "path2": "foo!bar"}

        Output:
        ["hello%20world", "foo%21bar"]

        Expression (array):
        encode_url(paths)

        Data:
        {"paths": ["hello world", "foo!bar"]}

        Output:
        ["hello%20world", "foo%21bar"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return urllib.parse.quote(values[0])
        return [urllib.parse.quote(item) if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string']}, {'types': ['string']})
    def _func_equal_fold(self, string1: str, string2: str) -> bool:
        """Case-insensitive string comparison.

        Returns true if both strings are equal regardless of letter case.

        Expression:
        equal_fold(dept, required_dept)

        Data:
        {"dept": "Engineering", "required_dept": "engineering"}

        Output:
        true
        """
        return string1.casefold() == string2.casefold()

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_lower(self, *args) -> str | list[str]:
        """Convert all characters to lowercase in one or more strings, or each string in an array.

        Expression (string):
        lower(name)

        Data:
        {"name": "John"}

        Output:
        "john"

        Expression (multiple):
        lower(first, last)

        Data:
        {"first": "JOHN", "last": "DOE"}

        Output:
        ["john", "doe"]

        Expression (array):
        lower(names)

        Data:
        {"names": ["John", "JANE"]}

        Output:
        ["john", "jane"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return values[0].lower()
        return [item.lower() if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string']}, {'types': ['string']})
    def _func_pattern_match(self, pattern: str, value: str) -> bool:
        """Simple wildcard pattern matching using * (any sequence) and ? (any single character).

        Expression:
        pattern_match('192.168.*', ip)

        Data:
        {"ip": "192.168.1.100"}

        Output:
        true
        """
        return fnmatch.fnmatch(value, pattern)

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_refang(self, *args) -> str | list[str]:
        """Refang one or more defanged URLs, IPs, domains, or emails to restore them.

        Reverses defang replacements: hxxp:// → http://, hxxps:// → https://,
        fxp:// → ftp://, [.] → ., [:] → :, [@] → @.

        Expression (string):
        refang(indicator)

        Data:
        {"indicator": "hxxps[:]//malicious[.]example[.]com"}

        Output:
        "https://malicious.example.com"

        Expression (multiple):
        refang(url, ip)

        Data:
        {"url": "hxxps[:]//evil[.]com", "ip": "192[.]168[.]1[.]1"}

        Output:
        ["https://evil.com", "192.168.1.1"]

        Expression (array):
        refang(indicators)

        Data:
        {"indicators": ["hxxps[:]//malicious[.]example[.]com", "192[.]168[.]1[.]1"]}

        Output:
        ["https://malicious.example.com", "192.168.1.1"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return Util.refang(values[0])
        return [Util.refang(item) if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string']}, {'types': ['string']})
    def _func_regex(self, pattern: str, value: str) -> Any:
        r"""Match a regular expression against a string.

        Returns the list of capture groups if any are defined, the full match
        string if no groups are defined, or null if no match is found.

        Expression:
        regex('IP:(\\d+\\.\\d+\\.\\d+\\.\\d+)', text)

        Data:
        {"text": "Connection from IP:192.168.1.1"}

        Output:
        ["192.168.1.1"]
        """
        match = re.search(pattern, value)
        if not match:
            return None
        return list(match.groups()) if match.groups() else match.group(0)

    @functions.signature({'types': ['string']}, {'types': ['string', 'number']})
    def _func_regex_match(self, pattern: str, value: Any) -> bool:
        """Test whether the input string (or number) matches the regular expression pattern.

        Returns true if any part of the input matches; use anchors (^ and $) for
        full-string matching.

        Expression:
        regex_match('^[0-9]+$', port)

        Data:
        {"port": "8080"}

        Output:
        true
        """
        return bool(re.search(pattern, str(value)))

    @functions.signature(
        {'types': ['string']}, {'types': ['string', 'array']}, {'types': ['string']}
    )
    def _func_regex_replace(
        self, pattern: str, value: str | list[str], replacement: str
    ) -> str | list[str]:
        r"""Replace substrings matching a regular expression in a string or each string in an array.

        Expression (string):
        regex_replace('Ban\w+', text, 'Apple')

        Data:
        {"text": "Banana Banana"}

        Output:
        "Apple Apple"

        Expression (array):
        regex_replace('Ban\w+', texts, 'Apple')

        Data:
        {"texts": ["Banana Banana", "Banjo"]}

        Output:
        ["Apple Apple", "Apple"]
        """
        if isinstance(value, list):
            return [
                re.sub(pattern, replacement, item) if isinstance(item, str) else item
                for item in value
            ]
        return re.sub(pattern, replacement, value)

    @functions.signature({'types': ['string']}, {'types': ['string']}, {'types': ['string']})
    def _func_replace(self, input_: str, search: str, replacement: str, count: int = -1) -> str:
        """Replace all occurrences of a substring with a replacement string.

        Expression:
        replace('hello world', 'world', 'there')

        Output:
        "hello there"
        """
        return input_.replace(search, replacement, count)

    @functions.signature(
        {'types': ['string', 'array']},
        {'types': ['null', 'string'], 'optional': True},
    )
    def _func_split(
        self, value: str | list[str], delimiter: str | None = ','
    ) -> list[str] | list[list[str]]:
        """Split a string (or each string in an array) into a list using a delimiter.

        Default delimiter is a comma.

        Expression (string):
        split(departments)

        Data:
        {"departments": "finance,hr,r&d"}

        Output:
        ["finance", "hr", "r&d"]

        Expression (array):
        split(department_lists)

        Data:
        {"department_lists": ["finance,hr", "r&d,ops"]}

        Output:
        [["finance", "hr"], ["r&d", "ops"]]
        """
        if isinstance(value, list):
            return [item.split(delimiter) if isinstance(item, str) else item for item in value]
        return value.split(delimiter)

    @functions.signature({'types': ['string']}, {'types': ['array', 'object']})
    def _func_string_interpolate(self, template: str, params: list | dict) -> str:
        """Replace positional or named tokens in a template string.

        Tokens are matched by index ({0}, {1}, ...) when params is an array,
        or by key name ({key}) when params is an object.

        Expression:
        string_interpolate('Hello, {name}!', {"name": "World"})

        Output:
        "Hello, World!"
        """
        if isinstance(params, list):
            result = template
            for i, val in enumerate(params):
                result = result.replace(f'{{{i}}}', str(val) if val is not None else '')
            return result
        result = template
        for key, val in params.items():
            result = result.replace(f'{{{key}}}', str(val) if val is not None else '')
        return result

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_trim(self, *args) -> str | list[str]:
        """Remove leading and trailing whitespace.

        Remove leading and trailing whitespace from one or more strings, or each string
        in an array.

        Expression (string):
        trim(message)

        Data:
        {"message": "  hello  "}

        Output:
        "hello"

        Expression (multiple):
        trim(first, last)

        Data:
        {"first": "  hello  ", "last": "  world  "}

        Output:
        ["hello", "world"]

        Expression (array):
        trim(messages)

        Data:
        {"messages": ["  hello  ", "  world  "]}

        Output:
        ["hello", "world"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return values[0].strip()
        return [item.strip() if isinstance(item, str) else item for item in values]

    @functions.signature({'types': ['string', 'array'], 'variadic': True})
    def _func_upper(self, *args) -> str | list[str]:
        """Convert all characters to uppercase in one or more strings, or each string in an array.

        Expression (string):
        upper(name)

        Data:
        {"name": "john"}

        Output:
        "JOHN"

        Expression (multiple):
        upper(first, last)

        Data:
        {"first": "john", "last": "doe"}

        Output:
        ["JOHN", "DOE"]

        Expression (array):
        upper(names)

        Data:
        {"names": ["john", "jane"]}

        Output:
        ["JOHN", "JANE"]
        """
        values: list[Any] = []
        for arg in args:
            if isinstance(arg, list):
                values.extend(arg)
            else:
                values.append(arg)
        if len(values) == 1 and isinstance(values[0], str):
            return values[0].upper()
        return [item.upper() if isinstance(item, str) else item for item in values]
