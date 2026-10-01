"""Shared helpers for the Python ports of the security-audit validators.

This module mirrors the helpers that the upstream Node validators keep
byte-for-byte aligned with each other (the Unicode character classes, the
diagnostic escaping, the safe relative path predicate, the safe input reader
and the error collector).  Both ``validate-findings.py`` and
``validate-coverage-ledger.py`` import from here so the two implementations can
never drift apart.

Only the Python standard library is used.
"""

import errno
import json
import math
import os
import re
import unicodedata
from decimal import Decimal

MAX_DIAGNOSTIC_STRING_LENGTH = 256

# \p{White_Space} as reported by the reference engine (Unicode 16.0).
_WHITE_SPACE_RANGES = (
    (0x0009, 0x000D),
    (0x0020, 0x0020),
    (0x0085, 0x0085),
    (0x00A0, 0x00A0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
)

# \p{Default_Ignorable_Code_Point} (derived property, not exposed by
# unicodedata, so the exact ranges are embedded).
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# JavaScript's /\s/ (Whitespace + LineTerminator), which differs from Python's
# str.isspace() (no U+0085, but it does include U+FEFF).
_JS_WHITESPACE_RANGES = (
    (0x0009, 0x000D),
    (0x0020, 0x0020),
    (0x00A0, 0x00A0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
    (0xFEFF, 0xFEFF),
)


def _expand(ranges):
    values = set()
    for start, end in ranges:
        values.update(range(start, end + 1))
    return frozenset(values)


WHITE_SPACE = _expand(_WHITE_SPACE_RANGES)
DEFAULT_IGNORABLE = _expand(_DEFAULT_IGNORABLE_RANGES)
JS_WHITESPACE = _expand(_JS_WHITESPACE_RANGES)

WINDOWS_RESERVED_COMPONENT = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)",
    re.IGNORECASE,
)
IDENTIFIER_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
ARRAY_INDEX_KEY = re.compile(r"(?:0|[1-9][0-9]*)$")


class _Undefined:
    """Singleton standing in for JavaScript ``undefined``."""

    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()


class SafeInputError(Exception):
    """Raised when an input cannot be opened or read under the safety rules."""


class JsonStructureError(Exception):
    """Raised when the JSON text preflight rejects the input structure."""


def js_string(value):
    """Mirror JavaScript ``String(value)`` for the value shapes we handle."""
    if value is None:
        return "null"
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return js_number_to_string(value)
    if isinstance(value, list):
        return ",".join(
            "" if entry is None else js_string(entry) for entry in value
        )
    if value is UNDEFINED:
        return "undefined"
    return "[object Object]"


def js_number_to_string(value):
    """Mirror JavaScript ``String(Number)`` (ECMA Number::toString)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, float):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "0"
    negative = value < 0
    decomposition = Decimal(repr(abs(value)))
    _, digits, exponent = decomposition.as_tuple()
    text = "".join(str(digit) for digit in digits)
    stripped = text.rstrip("0") or "0"
    exponent += len(text) - len(stripped)
    significant = stripped
    k = len(significant)
    n = k + exponent
    if k <= n <= 21:
        body = significant + "0" * (n - k)
    elif 0 < n <= 21:
        body = significant[:n] + "." + significant[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + significant
    else:
        power = n - 1
        mantissa = significant if k == 1 else significant[0] + "." + significant[1:]
        body = mantissa + "e" + ("+" if power >= 0 else "-") + str(abs(power))
    return ("-" if negative else "") + body


def js_json_stringify(value):
    """Mirror ``JSON.stringify`` for a string (non-ASCII kept literal)."""
    out = ['"']
    for character in value:
        code = ord(character)
        if character == '"':
            out.append('\\"')
        elif character == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(_CONTROL_ESCAPES.get(code, "\\u%04x" % code))
        elif 0xD800 <= code <= 0xDFFF:
            out.append("\\u%04x" % code)
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


_CONTROL_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def js_json_stringify_value(value):
    """Mirror ``JSON.stringify`` for the JSON value shapes used in keys."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return js_json_stringify(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return "null"
        return js_number_to_string(value)
    if isinstance(value, list):
        return "[" + ",".join(
            "null" if entry is None else js_json_stringify_value(entry)
            for entry in value
        ) + "]"
    if isinstance(value, dict):
        parts = []
        for key in js_object_keys(value):
            parts.append(js_json_stringify(key) + ":" + js_json_stringify_value(value[key]))
        return "{" + ",".join(parts) + "}"
    return "null"


def _utf16_units(value):
    raw = value.encode("utf-16-le", "surrogatepass")
    return [raw[index] | (raw[index + 1] << 8) for index in range(0, len(raw), 2)]


def _units_to_string(units):
    raw = bytearray()
    for unit in units:
        raw.append(unit & 0xFF)
        raw.append((unit >> 8) & 0xFF)
    return bytes(raw).decode("utf-16-le", "surrogatepass")


def _has_surrogate(value):
    for character in value:
        code = ord(character)
        if 0xD800 <= code <= 0xDFFF:
            return True
    return False


def iter_code_points(value):
    """Yield code points the way a JavaScript /u regex scans the string."""
    if not _has_surrogate(value):
        for character in value:
            yield ord(character)
        return
    units = _utf16_units(value)
    index = 0
    total = len(units)
    while index < total:
        first = units[index]
        index += 1
        if 0xD800 <= first <= 0xDBFF and index < total and 0xDC00 <= units[index] <= 0xDFFF:
            second = units[index]
            index += 1
            yield 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        else:
            yield first


def js_length(value):
    """JavaScript ``value.length`` (UTF-16 code units)."""
    extra = 0
    for character in value:
        if ord(character) > 0xFFFF:
            extra += 1
    return len(value) + extra


def has_valid_unicode_scalar_values(value):
    if not _has_surrogate(value):
        return True
    units = _utf16_units(value)
    index = 0
    total = len(units)
    while index < total:
        first = units[index]
        index += 1
        if 0xD800 <= first <= 0xDBFF:
            if index >= total:
                return False
            second = units[index]
            index += 1
            if second < 0xDC00 or second > 0xDFFF:
                return False
        elif 0xDC00 <= first <= 0xDFFF:
            return False
    return True


def code_point_length(value):
    if not _has_surrogate(value):
        return len(value)
    units = _utf16_units(value)
    length = 0
    index = 0
    total = len(units)
    while index < total:
        first = units[index]
        index += 1
        if 0xD800 <= first <= 0xDBFF and index < total:
            second = units[index]
            if 0xDC00 <= second <= 0xDFFF:
                index += 1
        length += 1
    return length


def _category(code):
    return unicodedata.category(chr(code))


def visible_content_match(value):
    """``VISIBLE_CONTENT.test(value)`` — any non-invisible code point."""
    for code in iter_code_points(value):
        if code in WHITE_SPACE or code in DEFAULT_IGNORABLE:
            continue
        if _category(code) in ("Cc", "Cf"):
            continue
        return True
    return False


def path_forbidden_match(value):
    """``PATH_FORBIDDEN_CHARACTER.test(value)``."""
    for code in iter_code_points(value):
        if code in DEFAULT_IGNORABLE:
            return True
        if _category(code) in ("Cc", "Cf", "Zl", "Zp"):
            return True
    return False


def unsafe_diagnostic_match(value):
    """``UNSAFE_DIAGNOSTIC_CHARACTER.test(value)``."""
    for code in iter_code_points(value):
        if code in DEFAULT_IGNORABLE:
            return True
        if _category(code) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def escape_unsafe_diagnostic_characters(value):
    text = value if isinstance(value, str) else js_string(value)
    out = []
    for code in iter_code_points(text):
        if code in DEFAULT_IGNORABLE or _category(code) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            out.append("\\u%04x" % code if code <= 0xFFFF else "\\u{%x}" % code)
        else:
            out.append(chr(code))
    return "".join(out)


def has_visible_prose(value):
    return has_valid_unicode_scalar_values(value) and visible_content_match(value)


def is_visible_text(value, max_length=4096):
    """``isVisibleText`` shared by the coverage-ledger validator."""
    return (
        isinstance(value, str)
        and len(value) > 0
        and len(value) <= max_length
        and js_trim(value) == value
        and has_visible_prose(value)
    )


def clip_diagnostic_string(value):
    if js_length(value) <= MAX_DIAGNOSTIC_STRING_LENGTH:
        return value
    return _units_to_string(_utf16_units(value)[:MAX_DIAGNOSTIC_STRING_LENGTH]) + "..."


def safe_quote(value):
    if isinstance(value, str):
        serialized = js_json_stringify(clip_diagnostic_string(value))
    elif value is None:
        serialized = "null"
    elif isinstance(value, bool):
        serialized = "true" if value else "false"
    elif is_finite_number(value):
        serialized = js_number_to_string(value)
    elif isinstance(value, list):
        serialized = '"<array>"'
    elif isinstance(value, dict):
        serialized = '"<object>"'
    elif value is UNDEFINED:
        serialized = '"<undefined>"'
    else:
        serialized = '"<%s>"' % type_of(value)
    return escape_unsafe_diagnostic_characters(serialized)


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_finite_number(value):
    return is_number(value) and math.isfinite(float(value))


def number_is_integer(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return False


def set_has(collection, value):
    """Membership that mirrors ``Set.has`` for values Python cannot hash."""
    try:
        return value in collection
    except TypeError:
        return False


def same_value_zero(left, right):
    """ECMAScript SameValueZero (what ``Set`` membership uses).

    Objects and arrays compare by identity, as in JavaScript, so two distinct
    parsed containers that happen to be structurally equal do not match.
    """
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        return left is right
    if isinstance(left, float) and isinstance(right, float):
        if math.isnan(left) and math.isnan(right):
            return True
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if left is None or right is None:
        return left is None and right is None
    try:
        return left == right
    except TypeError:
        return left is right


def collection_has(values, target):
    """``new Set(values).has(target)`` without requiring hashable members."""
    for value in values:
        if same_value_zero(value, target):
            return True
    return False


def js_truthy(value):
    """JavaScript truthiness."""
    if value is None or value is UNDEFINED:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0 and not (isinstance(value, float) and math.isnan(value))
    if isinstance(value, str):
        return value != ""
    return True


def get_prop(value, key):
    """JavaScript property read: missing or non-object yields ``undefined``."""
    if isinstance(value, dict) and key in value:
        return value[key]
    return UNDEFINED


def type_of(value):
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    return "object"


def deep_equal(left, right):
    if left is right:
        return True
    left_type = type_of(left)
    if left_type != type_of(right):
        return False
    if left_type == "array":
        return len(left) == len(right) and all(
            deep_equal(entry, right[index]) for index, entry in enumerate(left)
        )
    if left_type == "object":
        left_keys = js_object_keys(left)
        right_keys = js_object_keys(right)
        return len(left_keys) == len(right_keys) and all(
            key in right and deep_equal(left[key], right[key]) for key in left_keys
        )
    if left_type == "number":
        return left == right
    return left == right


def js_object_keys(value):
    """Mirror the ``Object.keys`` ordering: integer indices first, ascending."""
    integer_keys = []
    other_keys = []
    for key in value:
        if len(key) <= 10 and ARRAY_INDEX_KEY.match(key):
            number = int(key)
            if number < 4294967295:
                integer_keys.append((number, key))
                continue
        other_keys.append(key)
    integer_keys.sort(key=lambda item: item[0])
    return [key for _, key in integer_keys] + other_keys


def property_path(base, key):
    if IDENTIFIER_KEY.match(key):
        return "%s.%s" % (base, key)
    return "%s[%s]" % (base, safe_quote(key))


def is_js_whitespace(character):
    return ord(character) in JS_WHITESPACE


def js_trim(value):
    """Mirror JavaScript ``String.prototype.trim``."""
    start = 0
    end = len(value)
    while start < end and is_js_whitespace(value[start]):
        start += 1
    while end > start and is_js_whitespace(value[end - 1]):
        end -= 1
    return value[start:end]


def is_safe_relative_path(value):
    if (
        not isinstance(value, str)
        or value == ""
        or not has_valid_unicode_scalar_values(value)
        or js_trim(value) != value
        or path_forbidden_match(value)
        or "\\" in value
        or ":" in value
    ):
        return False
    if value.startswith("/") or value.startswith("~"):
        return False
    for segment in value.split("/"):
        if segment in ("", ".", ".."):
            return False
        if segment[-1] in (" ", "."):
            return False
        if WINDOWS_RESERVED_COMPONENT.match(segment):
            return False
    return True


class ErrorList(list):
    """A list that caps total length and escapes every pushed diagnostic."""

    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def push(self, *messages):
        remaining = self.cap - len(self)
        if remaining > 0:
            for message in messages[:remaining]:
                list.append(self, escape_unsafe_diagnostic_characters(message))
        return len(self)


def create_error_list(cap):
    return ErrorList(cap)


def read_file_within_limit(path, limit_bytes):
    no_follow = getattr(os, "O_NOFOLLOW", 0) or 0
    non_block = getattr(os, "O_NONBLOCK", 0) or 0
    if no_follow == 0 or non_block == 0:
        raise SafeInputError("OS no-follow and nonblocking input protection is unavailable")

    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | non_block)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise SafeInputError("input must not be a symlink")
        raise

    try:
        info = os.fstat(descriptor)
        if (info.st_mode & 0o170000) != 0o100000:
            raise SafeInputError("input must be a regular file")
        if info.st_size > limit_bytes:
            raise SafeInputError("input exceeds %d byte limit" % limit_bytes)

        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit_bytes:
                raise SafeInputError("input exceeds %d byte limit" % limit_bytes)
            chunks.append(chunk)
        data = b"".join(chunks)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise SafeInputError("input is not valid UTF-8")
    finally:
        os.close(descriptor)


def load_json_text(contents):
    """``JSON.parse`` semantics: reject NaN/Infinity, numbers become doubles."""

    def reject_constant(token):
        raise ValueError("invalid constant " + token)

    return json.loads(contents, parse_int=float, parse_float=float, parse_constant=reject_constant)
