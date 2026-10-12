"""Conservative evaluation with persistent, versioned, per-attack caching."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from decimal import Decimal
import os
from pathlib import Path
import sqlite3
from typing import Iterable, Optional, Union

from .backend import EstimationError, Estimator, UnsupportedParameters
from .parameters import Parameters
from .results import AttackEstimate, Estimate, Evaluation
from ._serialization import dumps


def default_jobs():
    return min(4, os.cpu_count() or 1)


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
        connection.execute("CREATE TABLE IF NOT EXISTS attacks_v1 "
                           "(key TEXT PRIMARY KEY, security_bits TEXT NOT NULL)")
        connection.commit()
        yield connection
    finally:
        connection.close()


def _run(estimator, parameters, name):
    result = estimator.attack(parameters, name)
    if not isinstance(result, AttackEstimate) or result.attack != name:
        raise EstimationError(f"{estimator.name} returned a mismatched result for {name}.")
    return result


def evaluate(parameters: Parameters, estimators: Iterable[Estimator], *,
             cache: Union[bool, str, Path] = True, jobs: Optional[int] = None,
             target=None) -> Evaluation:
    """Evaluate the selected attacks of applicable backends with a common cost model.

    cache=True uses $XDG_CACHE_HOME/ckks-estimator/estimates.sqlite3,
    falling back to ~/.cache. A path selects another database.
    cache=False disables both cache reads and writes.

    jobs attacks run in parallel. Default: at most 4. With a target, stop at
    the first attack below it and return an incomplete Evaluation.
    """
    jobs = default_jobs() if jobs is None else jobs
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer.")
    if target is not None:
        target = Decimal(str(target))
        if target.is_nan():
            raise ValueError("target must not be NaN.")
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
    for estimator in applicable:
        names = tuple(estimator.attacks)
        if not names or len(set(names)) != len(names):
            raise ValueError(f"{estimator.name} must select distinct attacks.")

    results, pending = {}, []
    refuted = False

    with _database(cache) as database:
        def record(task, result, key=None):
            nonlocal refuted
            results[task] = result
            if target is not None and result.security_bits < target:
                refuted = True
            if key is not None and database is not None:
                with database:
                    database.execute("INSERT OR REPLACE INTO attacks_v1 VALUES (?, ?)",
                                     (key, str(result.security_bits)))

        for index, estimator in enumerate(applicable):
            for name in estimator.attacks:
                key = dumps((parameters, estimator.name, estimator.revision, estimator.cost_model,
                             dict(estimator.configuration), name))
                row = None if database is None else database.execute(
                    "SELECT security_bits FROM attacks_v1 WHERE key = ?", (key,)).fetchone()
                if row is None:
                    pending.append(((index, name), key))
                else:
                    record((index, name), AttackEstimate(name, row[0]))

        if refuted:
            pending = []
        if jobs == 1 or len(pending) < 2:
            for task, key in pending:
                record(task, _run(applicable[task[0]], parameters, task[1]), key)
                if refuted:
                    break
        else:
            pool = ThreadPoolExecutor(min(jobs, len(pending)))
            futures = {pool.submit(_run, applicable[task[0]], parameters, task[1]): (task, key)
                       for task, key in pending}
            try:
                for future in as_completed(futures):
                    task, key = futures[future]
                    record(task, future.result(), key)
                    if refuted:
                        break
            finally:
                # On refutation, failure, or interruption, abandon queued and running attacks.
                if not all(future.done() for future in futures):
                    for future in futures:
                        future.cancel()
                    for estimator in applicable:
                        cancel = getattr(estimator, "cancel", None)
                        if cancel is not None:
                            cancel()
                pool.shutdown(wait=True)
                # Keep attacks that finished before they could be abandoned.
                for future, (task, key) in futures.items():
                    if task not in results and not future.cancelled() and future.exception() is None:
                        record(task, future.result(), key)

    estimates = []
    for index, estimator in enumerate(applicable):
        attacks = tuple(results[index, name] for name in estimator.attacks if (index, name) in results)
        if attacks:
            estimates.append(Estimate(parameters, estimator.name, estimator.revision,
                                      estimator.cost_model, attacks, estimator.configuration))
    complete = sum(len(estimate.attacks) for estimate in estimates) == \
        sum(len(tuple(estimator.attacks)) for estimator in applicable)
    return Evaluation(tuple(estimates), tuple(unsupported), complete)
