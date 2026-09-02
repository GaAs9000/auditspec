"""Closed primitive wire types used by the Phase 1 Core kernel."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from typing import Any

from .canonical import IJSON_MAX, canonical_json

REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:@-]*$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANT_RE = re.compile(
    r"^(?!0000)[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{9}Z$"
)


class WireError(ValueError):
    pass


def require_ref(value: Any, field: str = "ref") -> str:
    if not isinstance(value, str) or REF_RE.fullmatch(value) is None:
        raise WireError(f"{field} is not a Core ref")
    return value


def require_digest(value: Any, field: str = "digest") -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise WireError(f"{field} is not a lowercase SHA-256 digest")
    return value


def require_int(
    value: Any, field: str = "integer", *, nonnegative: bool = False
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WireError(f"{field} must be an integer")
    lower = 0 if nonnegative else -IJSON_MAX
    if not lower <= value <= IJSON_MAX:
        raise WireError(f"{field} is outside the Core integer range")
    return value


def require_exact_keys(value: Any, required: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WireError(f"{field} must be an object")
    if set(value) != required:
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        raise WireError(f"{field} key mismatch: missing={missing}, extra={extra}")
    return value


def require_instant(value: Any, field: str = "instant") -> dict[str, str]:
    raw = require_exact_keys(value, {"rfc3339_utc"}, field)
    text = raw["rfc3339_utc"]
    if not isinstance(text, str) or INSTANT_RE.fullmatch(text) is None:
        raise WireError(f"{field} is not a canonical nanosecond UTC instant")
    try:
        datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise WireError(f"{field} contains an invalid Gregorian date") from exc
    return {"rfc3339_utc": text}


def require_anchored_time(value: Any, field: str = "anchored_time") -> dict[str, Any]:
    raw = require_exact_keys(value, {"instant", "monotonic_run_ns", "anchor_id"}, field)
    return {
        "instant": require_instant(raw["instant"], f"{field}.instant"),
        "monotonic_run_ns": require_int(
            raw["monotonic_run_ns"], f"{field}.monotonic_run_ns", nonnegative=True
        ),
        "anchor_id": require_ref(raw["anchor_id"], f"{field}.anchor_id"),
    }


@dataclass(frozen=True)
class ExactDecimal:
    coefficient: int
    scale: int

    def __post_init__(self) -> None:
        require_int(self.coefficient, "decimal.coefficient")
        require_int(self.scale, "decimal.scale", nonnegative=True)
        if self.scale > 0 and self.coefficient % 10 == 0:
            raise WireError("decimal is not normalized")

    @classmethod
    def parse(cls, value: str) -> "ExactDecimal":
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value) is None
        ):
            raise WireError(f"invalid exact decimal spelling: {value!r}")
        sign = -1 if value.startswith("-") else 1
        unsigned = value.lstrip("+-")
        if "." in unsigned:
            integer, fraction = unsigned.split(".", 1)
            coefficient = sign * int(integer + fraction)
            scale = len(fraction)
        else:
            coefficient = sign * int(unsigned)
            scale = 0
        while scale > 0 and coefficient % 10 == 0:
            coefficient //= 10
            scale -= 1
        return cls(coefficient, scale)

    @classmethod
    def from_wire(cls, value: Any) -> "ExactDecimal":
        raw = require_exact_keys(value, {"coefficient", "scale"}, "decimal")
        return cls(
            require_int(raw["coefficient"], "decimal.coefficient"),
            require_int(raw["scale"], "decimal.scale", nonnegative=True),
        )

    def to_wire(self) -> dict[str, int]:
        return {"coefficient": self.coefficient, "scale": self.scale}

    def as_fraction(self) -> Fraction:
        return Fraction(self.coefficient, 10**self.scale)

    def __add__(self, other: "ExactDecimal") -> "ExactDecimal":
        scale = max(self.scale, other.scale)
        left = self.coefficient * 10 ** (scale - self.scale)
        right = other.coefficient * 10 ** (scale - other.scale)
        coefficient = left + right
        while scale > 0 and coefficient % 10 == 0:
            coefficient //= 10
            scale -= 1
        return ExactDecimal(coefficient, scale)


SCALAR_NAMES = {
    "boolean",
    "integer",
    "string",
    "bytes",
    "ref",
    "digest",
    "instant",
    "anchored_time",
    "decimal",
}


@dataclass(frozen=True)
class TypeNode:
    kind: str
    name: str | None = None
    item: "TypeNode | None" = None
    value: "TypeNode | None" = None
    schema: Any = None

    @classmethod
    def scalar(cls, name: str) -> "TypeNode":
        if name not in SCALAR_NAMES:
            raise WireError(f"unknown scalar type: {name}")
        return cls("scalar", name=name)

    @classmethod
    def from_wire(cls, value: Any, *, depth: int = 0) -> "TypeNode":
        if (
            depth > 32
            or not isinstance(value, dict)
            or not isinstance(value.get("kind"), str)
        ):
            raise WireError("invalid or over-deep TypeNode")
        kind = value["kind"]
        if kind == "scalar":
            require_exact_keys(value, {"kind", "name"}, "TypeNode.scalar")
            return cls.scalar(str(value["name"]))
        if kind in {"optional", "list", "set"}:
            require_exact_keys(value, {"kind", "item"}, f"TypeNode.{kind}")
            return cls(kind, item=cls.from_wire(value["item"], depth=depth + 1))
        if kind == "map":
            require_exact_keys(value, {"kind", "key", "value"}, "TypeNode.map")
            key = cls.from_wire(value["key"], depth=depth + 1)
            if key != cls.scalar("string"):
                raise WireError("Core map keys must be strings")
            return cls(
                kind, item=key, value=cls.from_wire(value["value"], depth=depth + 1)
            )
        if kind == "record":
            require_exact_keys(value, {"kind", "schema"}, "TypeNode.record")
            if not isinstance(value["schema"], dict):
                raise WireError("record schema must be a rooted_ref object")
            return cls(kind, schema=value["schema"])
        raise WireError(f"unknown TypeNode kind: {kind}")

    def to_wire(self) -> dict[str, Any]:
        if self.kind == "scalar":
            return {"kind": "scalar", "name": self.name}
        if self.kind in {"optional", "list", "set"}:
            assert self.item is not None
            return {"kind": self.kind, "item": self.item.to_wire()}
        if self.kind == "map":
            assert self.item is not None and self.value is not None
            return {
                "kind": "map",
                "key": self.item.to_wire(),
                "value": self.value.to_wire(),
            }
        if self.kind == "record":
            return {"kind": "record", "schema": self.schema}
        raise WireError(f"cannot serialize TypeNode kind: {self.kind}")


BOOLEAN = TypeNode.scalar("boolean")
INTEGER = TypeNode.scalar("integer")
STRING = TypeNode.scalar("string")
REF = TypeNode.scalar("ref")
DIGEST = TypeNode.scalar("digest")


def infer_scalar_type(values: list[Any]) -> TypeNode:
    if not values:
        raise WireError("cannot infer a type from an empty domain")
    if all(isinstance(value, bool) for value in values):
        return BOOLEAN
    if all(isinstance(value, int) and not isinstance(value, bool) for value in values):
        return INTEGER
    if all(isinstance(value, str) for value in values):
        return STRING
    raise WireError("finite domain has mixed or unsupported scalar types")


def canonical_value(value: Any, expected: TypeNode | None = None) -> dict[str, Any]:
    if value is None:
        result: dict[str, Any] = {"kind": "null"}
    elif isinstance(value, bool):
        result = {"kind": "bool", "value": value}
    elif isinstance(value, int) and not isinstance(value, bool):
        result = {"kind": "integer", "value": require_int(value)}
    elif isinstance(value, str):
        result = {"kind": "string", "value": value}
    elif isinstance(value, bytes):
        result = {"kind": "bytes", "value": {"hex": value.hex()}}
    elif isinstance(value, ExactDecimal):
        result = {"kind": "decimal", **value.to_wire()}
    elif (
        isinstance(value, dict)
        and expected is not None
        and expected.kind == "scalar"
        and expected.name == "instant"
    ):
        result = {"kind": "instant", "value": require_instant(value)}
    elif (
        isinstance(value, dict)
        and expected is not None
        and expected.kind == "scalar"
        and expected.name == "anchored_time"
    ):
        result = {"kind": "anchored_time", "value": require_anchored_time(value)}
    elif isinstance(value, list):
        item_type = (
            expected.item if expected is not None and expected.kind == "list" else None
        )
        result = {
            "kind": "list",
            "elements": [canonical_value(item, item_type) for item in value],
        }
    elif isinstance(value, (set, frozenset)):
        item_type = (
            expected.item if expected is not None and expected.kind == "set" else None
        )
        elements = [canonical_value(item, item_type) for item in value]
        elements.sort(key=canonical_json)
        if len({canonical_json(item) for item in elements}) != len(elements):
            raise WireError("canonical set contains duplicates")
        result = {"kind": "set", "elements": elements}
    elif isinstance(value, dict) and all(isinstance(key, str) for key in value):
        value_type = (
            expected.value if expected is not None and expected.kind == "map" else None
        )
        result = {
            "kind": "map",
            "entries": [
                {"key": key, "value": canonical_value(value[key], value_type)}
                for key in sorted(value, key=lambda item: item.encode("utf-8"))
            ],
        }
    else:
        raise WireError(f"unsupported canonical value: {value!r}")
    if expected is not None:
        _require_python_type(value, expected)
    return result


def decode_canonical_value(value: Any, expected: TypeNode) -> Any:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise WireError("invalid CanonicalValue")
    kind = value["kind"]
    if kind == "null":
        require_exact_keys(value, {"kind"}, "CanonicalValue.null")
        result = None
    elif kind == "bool":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.bool")
        if not isinstance(value["value"], bool):
            raise WireError("CanonicalValue.bool value is not boolean")
        result = value["value"]
    elif kind == "integer":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.integer")
        result = require_int(value["value"])
    elif kind == "string":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.string")
        if not isinstance(value["value"], str):
            raise WireError("CanonicalValue.string value is not text")
        result = value["value"]
    elif kind == "decimal":
        require_exact_keys(
            value, {"kind", "coefficient", "scale"}, "CanonicalValue.decimal"
        )
        result = ExactDecimal(
            require_int(value["coefficient"]),
            require_int(value["scale"], nonnegative=True),
        )
    elif kind == "bytes":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.bytes")
        raw = require_exact_keys(value["value"], {"hex"}, "CanonicalValue.bytes.value")
        if (
            not isinstance(raw["hex"], str)
            or re.fullmatch(r"(?:[0-9a-f]{2})*", raw["hex"]) is None
        ):
            raise WireError("CanonicalValue bytes are not lowercase even-length hex")
        result = bytes.fromhex(raw["hex"])
    elif kind == "instant":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.instant")
        result = require_instant(value["value"])
    elif kind == "anchored_time":
        require_exact_keys(value, {"kind", "value"}, "CanonicalValue.anchored_time")
        result = require_anchored_time(value["value"])
    elif kind in {"list", "set"}:
        require_exact_keys(value, {"kind", "elements"}, f"CanonicalValue.{kind}")
        if not isinstance(value["elements"], list):
            raise WireError("CanonicalValue elements must be a list")
        if expected.kind not in {"list", "set"} or expected.item is None:
            raise WireError("collection value/type mismatch")
        result_list = [
            decode_canonical_value(item, expected.item) for item in value["elements"]
        ]
        if kind == "set":
            encoded = [canonical_json(item) for item in value["elements"]]
            if encoded != sorted(encoded) or len(encoded) != len(set(encoded)):
                raise WireError("canonical set is not sorted-unique")
            result = frozenset(result_list)
        else:
            result = result_list
    elif kind == "map":
        require_exact_keys(value, {"kind", "entries"}, "CanonicalValue.map")
        if (
            expected.kind != "map"
            or expected.value is None
            or not isinstance(value["entries"], list)
        ):
            raise WireError("map value/type mismatch")
        result = {}
        prior: bytes | None = None
        for entry in value["entries"]:
            raw_entry = require_exact_keys(
                entry, {"key", "value"}, "CanonicalValue.map.entry"
            )
            if not isinstance(raw_entry["key"], str):
                raise WireError("CanonicalValue map key is not a string")
            key_bytes = raw_entry["key"].encode("utf-8")
            if prior is not None and key_bytes <= prior:
                raise WireError("CanonicalValue map keys are not sorted-unique")
            prior = key_bytes
            result[raw_entry["key"]] = decode_canonical_value(
                raw_entry["value"], expected.value
            )
    else:
        raise WireError(f"unsupported CanonicalValue kind: {kind}")
    _require_python_type(result, expected)
    return result


def _require_python_type(value: Any, expected: TypeNode) -> None:
    if expected.kind == "optional":
        if value is None:
            return
        assert expected.item is not None
        _require_python_type(value, expected.item)
        return
    if expected.kind == "scalar":
        matches = {
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "string": isinstance(value, str),
            "ref": isinstance(value, str) and REF_RE.fullmatch(value) is not None,
            "digest": isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None,
            "decimal": isinstance(value, ExactDecimal),
            "bytes": isinstance(value, bytes),
            "instant": isinstance(value, dict) and set(value) == {"rfc3339_utc"},
            "anchored_time": isinstance(value, dict)
            and set(value) == {"instant", "monotonic_run_ns", "anchor_id"},
        }.get(str(expected.name), True)
        if not matches:
            raise WireError(f"value does not match scalar type {expected.name}")
        return
    if expected.kind == "list" and not isinstance(value, list):
        raise WireError("value is not a list")
    if expected.kind == "set" and not isinstance(value, (set, frozenset)):
        raise WireError("value is not a set")
    if expected.kind == "map" and not isinstance(value, dict):
        raise WireError("value is not a map")
