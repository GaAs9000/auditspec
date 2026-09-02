"""Strict Core-profile RFC 8785 canonicalization and domain-separated hashes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

IJSON_MIN = -9_007_199_254_740_991
IJSON_MAX = 9_007_199_254_740_991


class CanonicalizationError(ValueError):
    """Raised when a value is outside the Core canonical wire profile."""


def _quote(value: str) -> str:
    pieces: list[str] = ['"']
    escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
    }
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalizationError("unpaired UTF-16 surrogate is forbidden")
        if character in escapes:
            pieces.append(escapes[character])
        elif codepoint <= 0x1F:
            pieces.append(f"\\u{codepoint:04x}")
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("object key contains an invalid surrogate") from exc


def canonical_json(value: Any) -> str:
    """Return RFC 8785 JSON under the stricter Core no-float profile.

    Core wire values use only JSON null/boolean/I-JSON integers/strings, lists,
    and string-keyed objects. Exact decimals and bytes are tagged objects, so a
    native floating-point value is always an error.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not IJSON_MIN <= value <= IJSON_MAX:
            raise CanonicalizationError("integer is outside the I-JSON safe range")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("floating JSON numbers are forbidden")
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise CanonicalizationError("bytes require the tagged {hex: ...} wire form")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("JSON object keys must be strings")
        keys = sorted(value, key=_utf16_sort_key)
        return (
            "{"
            + ",".join(f"{_quote(key)}:{canonical_json(value[key])}" for key in keys)
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    raise CanonicalizationError(
        f"unsupported canonical JSON type: {type(value).__name__}"
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def digest(domain: str, value: Any) -> str:
    if not isinstance(domain, str) or not domain:
        raise CanonicalizationError("digest domain must be a non-empty string")
    return hashlib.sha256(
        domain.encode("utf-8") + b"\x00" + canonical_bytes(value)
    ).hexdigest()


def raw_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json_loads(text: str) -> Any:
    """Load JSON while rejecting duplicate keys, floats, constants, and bad wire values."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalizationError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    def reject_float(value: str) -> Any:
        raise CanonicalizationError(f"floating JSON number is forbidden: {value}")

    def reject_constant(value: str) -> Any:
        raise CanonicalizationError(f"non-finite JSON constant is forbidden: {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalizationError("invalid JSON") from exc
    canonical_json(value)
    return value


def legacy_json_value(value: Any) -> Any:
    """Explicitly crosswalk legacy Python containers into JSON wire containers."""

    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("legacy mapping has a non-string key")
        return {key: legacy_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [legacy_json_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            "legacy float needs an explicit exact-decimal crosswalk"
        )
    raise CanonicalizationError(
        f"legacy value has no JSON crosswalk: {type(value).__name__}"
    )
