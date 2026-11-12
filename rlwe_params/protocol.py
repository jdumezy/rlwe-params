"""The JSON-lines protocol between rlwe-params and estimator backends.

A backend is any program, in any language, that reads one JSON request per
line on stdin and writes one JSON response per line on stdout. Requests are

    {"op": "describe", "options": {...}}
    {"op": "supports", "options": {...}, "parameters": {...}}
    {"op": "attack", "options": {...}, "parameters": {...}, "attack": "usvp"}

and responses are {"result": ...} or {"error": {"kind": ..., "message": ...}},
where kind is "unsupported", "invalid", or "failed". describe returns name,
revision, cost_model, configuration, and attacks. supports returns a boolean.
attack returns the log2 cost as a decimal string, rounded down, or "Infinity".
Parameters encode n and samples as integers, q as a decimal string, and each
distribution as an object with a "type" field.
"""

from contextlib import redirect_stdout
from decimal import Decimal
import json
import sys
import traceback

from .backend import EstimationError, UnsupportedParameters
from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform


VERSION = 1


def canonical(value) -> str:
    """Deterministic JSON, used for cache keys and adapter options."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def encode_distribution(distribution) -> dict:
    if isinstance(distribution, SparseTernary):
        return {"type": "sparse_ternary", "positive": distribution.positive,
                "negative": distribution.negative}
    if isinstance(distribution, Ternary):
        return {"type": "ternary"}
    if isinstance(distribution, Uniform):
        return {"type": "uniform", "lower": distribution.lower, "upper": distribution.upper}
    if isinstance(distribution, DiscreteGaussian):
        return {"type": "discrete_gaussian", "stddev": str(distribution.stddev)}
    raise TypeError(f"Unsupported distribution {distribution!r}.")


def decode_distribution(data: dict):
    kind = data["type"]
    if kind == "sparse_ternary":
        return SparseTernary(data["positive"], data["negative"])
    if kind == "ternary":
        return Ternary()
    if kind == "uniform":
        return Uniform(data["lower"], data["upper"])
    if kind == "discrete_gaussian":
        return DiscreteGaussian(data["stddev"])
    raise ValueError(f"Unknown distribution type {kind!r}.")


def encode_parameters(parameters: Parameters) -> dict:
    return {"n": parameters.n, "q": str(parameters.q),
            "secret": encode_distribution(parameters.secret),
            "error": encode_distribution(parameters.error), "samples": parameters.samples}


def decode_parameters(data: dict) -> Parameters:
    return Parameters(data["n"], int(data["q"]), decode_distribution(data["secret"]),
                      decode_distribution(data["error"]), data["samples"])


def _error(exc):
    if isinstance(exc, UnsupportedParameters):
        kind = "unsupported"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        kind = "invalid"
    else:
        kind = "failed"
    return {"kind": kind, "message": str(exc)}


def serve(adapter, stdin=None, stdout=None) -> None:
    """Answer requests for a Python adapter class until stdin closes.

    adapter(**options) provides name, revision, cost_model, configuration,
    attacks, supports(parameters), and attack(parameters, name), which returns
    an AttackEstimate or a Decimal. Instances are reused for equal options.
    Anything the estimator prints goes to stderr.
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    instances = {}
    for line in stdin:
        try:
            request = json.loads(line)
            options = request.get("options", {})
            with redirect_stdout(sys.stderr):
                key = canonical(options)
                if key not in instances:
                    instances[key] = adapter(**options)
                instance = instances[key]
                operation = request["op"]
                if operation == "describe":
                    result = {"name": instance.name, "revision": instance.revision,
                              "cost_model": instance.cost_model,
                              "configuration": instance.configuration,
                              "attacks": list(instance.attacks)}
                elif operation == "supports":
                    result = bool(instance.supports(decode_parameters(request["parameters"])))
                elif operation == "attack":
                    cost = instance.attack(decode_parameters(request["parameters"]), request["attack"])
                    result = str(Decimal(str(getattr(cost, "security_bits", cost))))
                else:
                    raise ValueError(f"Unknown operation {operation!r}.")
            response = {"result": result}
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            response = {"error": _error(exc)}
        stdout.write(canonical(response) + "\n")
        stdout.flush()


def raise_error(error: dict):
    """Raise the exception a backend reported."""
    kind = {"unsupported": UnsupportedParameters, "invalid": ValueError}.get(
        error.get("kind"), EstimationError)
    raise kind(error.get("message", "The backend reported an error."))
