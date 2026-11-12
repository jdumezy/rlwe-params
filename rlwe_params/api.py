"""Public parameter estimation and modulus search API."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal

from .evaluation import default_jobs, evaluate
from .parameters import Parameters
from .profiles import profile as _profile
from .search import search_logq


def estimate(parameters=None, *, n=None, q=None, secret=None, error=None,
             samples=None, profile="matzov", estimators=None, cache=True,
             jobs=None, target=None):
    """Estimate parameters or explicit n, q, secret, error, and sample count.

    Use every applicable backend of the profile, or explicit estimators that
    implement the Estimator protocol in any runtime. Return an Evaluation with
    security_bits and all per-backend attack results.
    jobs attacks run in parallel. With a target, stop at the first attack below it.
    """
    if parameters is None:
        parameters = Parameters(n, q, secret, error, samples)
    elif not isinstance(parameters, Parameters):
        raise TypeError("parameters must be a Parameters instance.")
    elif any(value is not None for value in (n, q, secret, error, samples)):
        raise ValueError("Supply either parameters or individual parameter fields.")
    if estimators is None:
        estimators = _profile(profile).estimators(parameters)
    return evaluate(parameters, estimators, cache=cache, jobs=jobs, target=target)


class _Selection:
    """An estimator restricted to some of its attacks. Cached costs are shared."""

    def __init__(self, estimator, attacks):
        self._estimator = estimator
        self.attacks = attacks

    def __getattr__(self, name):
        return getattr(self._estimator, name)


def max_logq(*, n, secret, error, upper, samples=None, target=128, lower=15,
             guess=None, window=2, profile="matzov", estimators=None, cache=True, jobs=None,
             progress=None, prior=()):
    """Search q=2**logq with search_logq(), returning a certified SearchResult.

    Use the same distributions, sample count, and backends at every point.
    Only the binding attacks run while locating the boundary. Every attack
    runs at the returned logq. Without a guess, start from a rough estimate
    for ternary secrets. progress, if given, receives each evaluated logq, its
    attack costs, and whether every attack was requested.

    Full evaluations start with the attacks cheapest at the nearest evaluated
    logq, so that a point below the target is refuted early. Attacks not yet
    evaluated follow, in the order of prior, a sequence of "estimator / attack"
    labels, such as the ranking from a similar search.
    """
    jobs = default_jobs() if jobs is None else jobs
    reference = Parameters(n, 2, secret, error, samples)
    estimators = tuple(_profile(profile).estimators(reference) if estimators is None else estimators)
    if len({estimator.name for estimator in estimators}) != len(estimators):
        raise ValueError("Estimator names must be distinct.")
    if guess is None and type(lower) is int and type(upper) is int:
        try:
            guess = max(lower, min(upper, int(Decimal("3.4") * n / Decimal(str(target)))))
        except ArithmeticError:
            pass

    pairs = {f"{estimator.name} / {attack}": (estimator.name, attack)
             for estimator in estimators for attack in estimator.attacks}
    position = {label: index for index, label in enumerate(prior)}
    seen = {}

    def ranking(point):
        def key(label):
            nearest = min(seen.get(label, {}).items(), key=lambda item: abs(item[0] - point),
                          default=None)
            return (0, nearest[1], 0) if nearest else (1, 0, position.get(label, len(position)))

        return [pairs[label] for label in sorted(pairs, key=key)]

    def run(request, workers):
        point, attacks = request
        selected = estimators if attacks is None else [
            _Selection(estimator, names) for estimator in estimators
            for names in [tuple(a for a in estimator.attacks if f"{estimator.name} / {a}" in attacks)]
            if names]
        evaluation = evaluate(replace(reference, q=1 << point), selected, cache=cache, jobs=workers,
                              target=target if attacks is None else None,
                              order=ranking(point) if attacks is None else ())
        costs = {f"{result.estimator} / {attack.attack}": attack.security_bits
                 for result in evaluation.estimates for attack in result.attacks}
        for label, bits in costs.items():
            seen.setdefault(label, {})[point] = bits
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
