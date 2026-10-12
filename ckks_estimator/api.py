"""Public parameter estimation and modulus search API."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal

from .evaluation import default_jobs, evaluate
from .installation import BACKENDS
from .parameters import Parameters
from .search import search_logq


def _default_estimators(parameters):
    from .estimators import SageEstimator

    return [SageEstimator(name) for name, backend in BACKENDS.items()
            if backend.applies is None or backend.applies(parameters)]


def estimate(parameters=None, *, n=None, q=None, secret=None, error=None,
             samples=None, estimators=None, cache=True,
             jobs=None, target=None):
    """Estimate parameters or explicit n, q, secret, error, and sample count.

    By default, use every applicable registered backend with the MATZOV cost model.
    Return an Evaluation with security_bits and all per-backend attack results.
    Explicit estimators may implement the Estimator protocol in any runtime.
    jobs attacks run in parallel. With a target, stop at the first attack below it.
    """
    if parameters is None:
        parameters = Parameters(n, q, secret, error, samples)
    elif not isinstance(parameters, Parameters):
        raise TypeError("parameters must be a Parameters instance.")
    elif any(value is not None for value in (n, q, secret, error, samples)):
        raise ValueError("Supply either parameters or individual parameter fields.")
    if estimators is None:
        estimators = _default_estimators(parameters)
    return evaluate(parameters, estimators, cache=cache, jobs=jobs, target=target)


class _Selection:
    """An estimator restricted to some of its attacks. Cached costs are shared."""

    def __init__(self, estimator, attacks):
        self._estimator = estimator
        self.attacks = attacks

    def __getattr__(self, name):
        return getattr(self._estimator, name)


def max_logq(*, n, secret, error, upper, samples=None, target=128, lower=15,
             guess=None, window=2, estimators=None, cache=True, jobs=None, progress=None):
    """Search q=2**logq with search_logq(), returning a certified SearchResult.

    Use the same distributions, sample count, and backends at every point.
    Only the binding attacks run while locating the boundary. Every attack
    runs at the returned logq. Without a guess, start from a rough estimate
    for ternary secrets. progress, if given, receives each evaluated logq, its
    attack costs, and whether every attack was requested.
    """
    jobs = default_jobs() if jobs is None else jobs
    reference = Parameters(n, 2, secret, error, samples)
    estimators = _default_estimators(reference) if estimators is None else tuple(estimators)
    if len({estimator.name for estimator in estimators}) != len(estimators):
        raise ValueError("Estimator names must be distinct.")
    if guess is None and type(lower) is int and type(upper) is int:
        try:
            guess = max(lower, min(upper, int(Decimal("3.4") * n / Decimal(str(target)))))
        except ArithmeticError:
            pass

    def run(request, workers):
        point, attacks = request
        selected = estimators if attacks is None else [
            _Selection(estimator, names) for estimator in estimators
            for names in [tuple(a for a in estimator.attacks if f"{estimator.name} / {a}" in attacks)]
            if names]
        evaluation = evaluate(replace(reference, q=1 << point), selected, cache=cache, jobs=workers,
                              target=target if attacks is None else None)
        costs = {f"{result.estimator} / {attack.attack}": attack.security_bits
                 for result in evaluation.estimates for attack in result.attacks}
        if progress is not None:
            progress(point, costs, attacks is None)
        return costs

    def batch(requests):
        if len(requests) < 2 or jobs == 1:
            return [run(request, jobs) for request in requests]
        with ThreadPoolExecutor(min(jobs, len(requests))) as pool:
            return list(pool.map(lambda request: run(request, 1), requests))

    return search_logq(batch, upper=upper, target=target, lower=lower, guess=guess,
                       window=window, batch=min(jobs, 2))
