"""Typed JSON for cache identities and backend messages."""

from dataclasses import fields
from decimal import Decimal
import json

from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform
from .results import AttackEstimate, Estimate, Evaluation


_TYPES = {cls.__name__: cls for cls in (
    Parameters, SparseTernary, Ternary, Uniform, DiscreteGaussian,
    AttackEstimate, Estimate, Evaluation,
)}


def _encode(value):
    if type(value).__name__ in _TYPES and type(value) is _TYPES[type(value).__name__]:
        values = {f.name: getattr(value, f.name) for f in fields(value)}
        if isinstance(value, AttackEstimate):
            values["security_bits"] = str(value.security_bits)
        return [type(value).__name__, [[key, _encode(item)] for key, item in values.items()]]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("Configuration keys must be strings.")
        return ["dict", [[key, _encode(value[key])] for key in sorted(value)]]
    if isinstance(value, (tuple, list)):
        return [type(value).__name__, [_encode(item) for item in value]]
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Configuration decimals must be finite.")
        return ["decimal", str(value)]
    if type(value) is int:
        return ["int", hex(value)]
    if value is None or type(value) in (str, bool, float):
        return [type(value).__name__, value]
    raise TypeError(f"Unsupported configuration value: {type(value).__name__}.")


def _decode(value):
    kind, payload = value
    if kind in _TYPES:
        return _TYPES[kind](**{key: _decode(item) for key, item in payload})
    if kind == "dict":
        return {key: _decode(item) for key, item in payload}
    if kind in ("list", "tuple"):
        items = [_decode(item) for item in payload]
        return tuple(items) if kind == "tuple" else items
    if kind == "decimal":
        return Decimal(payload)
    if kind == "int":
        return int(payload, 16)
    if kind in ("NoneType", "str", "bool", "float"):
        return payload
    raise ValueError(f"Unknown serialized type {kind!r}.")


def dumps(value):
    return json.dumps(_encode(value), allow_nan=False, separators=(",", ":"))


def loads(value):
    return _decode(json.loads(value))
