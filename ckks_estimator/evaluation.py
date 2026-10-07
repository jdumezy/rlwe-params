"""Conservative evaluation with persistent, versioned caching."""

from contextlib import contextmanager
from dataclasses import fields
from decimal import Decimal
import json
import os
from pathlib import Path
import sqlite3
from typing import Iterable, Union

from .backend import EstimationError, Estimator, UnsupportedParameters
from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform
from .results import AttackEstimate, Estimate, Evaluation


def _encode(value):
    if isinstance(value, (Parameters, SparseTernary, Ternary, Uniform, DiscreteGaussian)):
        return [type(value).__name__, [[f.name, _encode(getattr(value, f.name))]
                                      for f in fields(value)]]
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


def _key(parameters, name, revision, cost_model, configuration):
    return json.dumps(_encode((parameters, name, revision, cost_model, dict(configuration))),
                      allow_nan=False, separators=(",", ":"))


@contextmanager
def _database(cache):
    if cache is False:
        yield None
        return
    if cache is True:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        path = root / "ckks-estimator" / "estimates.sqlite3"
    else:
        path = Path(cache)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS estimates_v1 "
                           "(key TEXT PRIMARY KEY, attacks TEXT NOT NULL)")
        connection.commit()
        yield connection
    finally:
        connection.close()


def evaluate(parameters: Parameters, estimators: Iterable[Estimator], *,
             cache: Union[bool, str, Path] = True) -> Evaluation:
    """Evaluate applicable backends with a common cost model.

    cache=True uses $XDG_CACHE_HOME/ckks-estimator/estimates.sqlite3,
    falling back to ~/.cache. A path selects another database.
    cache=False disables both cache reads and writes.
    """
    applicable, unsupported = [], []
    for estimator in estimators:
        if estimator.supports(parameters):
            applicable.append(estimator)
        else:
            unsupported.append(estimator.name)
    if not applicable:
        raise UnsupportedParameters("No supplied estimator supports these parameters.")
    if len({estimator.cost_model for estimator in applicable}) != 1:
        raise ValueError("Aggregate only estimators with the same cost model.")

    estimates = []
    with _database(cache) as database:
        for estimator in applicable:
            key = _key(parameters, estimator.name, estimator.revision,
                       estimator.cost_model, estimator.configuration)
            row = None if database is None else database.execute(
                "SELECT attacks FROM estimates_v1 WHERE key = ?", (key,)
            ).fetchone()
            if row is not None:
                result = Estimate(parameters, estimator.name, estimator.revision,
                                  estimator.cost_model,
                                  tuple(AttackEstimate(*attack) for attack in json.loads(row[0])),
                                  estimator.configuration)
            else:
                result = estimator.estimate(parameters)
                if not isinstance(result, Estimate) or _key(
                    result.parameters, result.estimator, result.revision,
                    result.cost_model, result.configuration
                ) != key:
                    raise EstimationError(f"{estimator.name} returned mismatched result provenance.")
                if database is not None:
                    attacks = json.dumps([(a.attack, str(a.security_bits)) for a in result.attacks])
                    with database:
                        database.execute("INSERT OR REPLACE INTO estimates_v1 VALUES (?, ?)",
                                         (key, attacks))
            estimates.append(result)
    return Evaluation(tuple(estimates), tuple(unsupported))
