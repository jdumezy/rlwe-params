"""Two-phase boundary search for mostly decreasing security estimates."""

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from math import floor
from typing import Callable, Mapping, Optional, Sequence, Tuple


Request = Tuple[int, Optional[Tuple[str, ...]]]


@dataclass(frozen=True)
class SearchResult:
    """Largest logq before the first observed unsafe point, with every attack evaluated.

    complete lists the points where every attack was evaluated. At logq, none
    is below the target. At other points, costs holds only the attacks that were evaluated,
    so their minimum is an upper bound on security. An upper_bound result means
    the search limit is safe, not that the global maximum has been found.
    """

    logq: Optional[int]
    target: Decimal
    costs: Mapping[int, Mapping[str, Decimal]]
    complete: Tuple[int, ...]
    checked_interval: Tuple[int, int]
    status: str

    @property
    def evaluations(self) -> Mapping[int, Decimal]:
        return {point: min(costs.values()) for point, costs in self.costs.items()}

    @property
    def security_bits(self) -> Optional[Decimal]:
        return None if self.logq is None else min(self.costs[self.logq].values())

    @property
    def q(self) -> Optional[int]:
        return None if self.logq is None else 1 << self.logq


def search_logq(evaluate: Callable[[Sequence[Request]], Sequence[Mapping[str, Decimal]]], *,
                upper: int, target=128, lower: int = 15, guess: Optional[int] = None,
                window: int = 2, batch: int = 1) -> SearchResult:
    """Locate the boundary with the binding attacks, then evaluate every attack there.

    evaluate receives (logq, attacks) requests and returns the named attack
    costs for each. attacks=None requests every attack. That evaluation may stop
    early, provided it returns an attack below the target.

    The first point is fully evaluated and its cheapest attack becomes the
    surrogate. The surrogate locates adjacent safe and unsafe points, modelling
    1/bits as linear in logq. The boundary is then fully evaluated. An attack
    refuting it becomes the surrogate and the search resumes below. Finally the
    surrogate checks window points below the boundary. batch surrogate
    points are requested at once.
    Without a guess, start at the middle of the interval. Errors propagate.
    """
    for name, value, minimum in (("lower", lower, 1), ("upper", upper, lower),
                                 ("window", window, 0), ("batch", batch, 1)):
        if type(value) is not int or value < minimum:
            raise ValueError(f"{name} must be an integer >= {minimum}.")
    if guess is not None and (type(guess) is not int or not lower <= guess <= upper):
        raise ValueError("guess must be an integer within the search bounds.")
    target = Decimal(str(target))
    if not target.is_finite() or target <= 0:
        raise ValueError("target must be finite and positive.")
    known, complete, surrogate = {}, set(), []

    def store(point, costs):
        for attack, bits in costs.items():
            bits = Decimal(str(bits))
            if bits.is_nan() or bits < 0:
                raise ValueError("Security estimates must be nonnegative and not NaN.")
            known.setdefault(point, {})[attack] = bits

    def evaluate_all(point):
        (costs,) = evaluate([(point, None)])
        if not costs:
            raise ValueError("A full evaluation returned no attack.")
        store(point, costs)
        binding = min(known[point], key=lambda attack: (known[point][attack], attack))
        if known[point][binding] >= target:
            complete.add(point)
        if not surrogate or known[point][binding] < target:
            # Attacks that held here are assumed to hold below, so only this one is tracked.
            surrogate[:] = [binding]

    def probe(points):
        requests = [(point, tuple(attack for attack in surrogate if attack not in known.get(point, {})))
                    for point in points]
        requests = [request for request in requests if request[1]]
        for (point, attacks), costs in zip(requests, evaluate(requests)):
            if set(attacks) - set(costs):
                raise ValueError("An evaluation omitted a requested attack.")
            store(point, costs)

    def safe(point):
        costs = known.get(point, {})
        if any(bits < target for bits in costs.values()):
            return False
        if point in complete or all(attack in costs for attack in surrogate):
            return True
        return None

    def predict():
        """Smallest predicted crossing of a surrogate attack, each modelled from its own costs."""
        goal = 1 / Fraction(target)
        crossings = []
        for attack in surrogate:
            inverse = {point: 0 if costs[attack].is_infinite() else 1 / Fraction(costs[attack])
                       for point, costs in known.items() if costs.get(attack, 0) > 0}
            ranked = sorted(inverse, key=lambda point: (abs(inverse[point] - goal), point))
            if not ranked:
                continue
            first = ranked[0]
            second = next((point for point in ranked[1:]
                           if (inverse[point] - inverse[first]) * (point - first) > 0), None)
            if second is not None:
                crossings.append(first + (goal - inverse[first]) * (second - first) /
                                 (inverse[second] - inverse[first]))
            elif inverse[first]:
                # A single point: assume security inversely proportional to logq.
                crossings.append(first * goal / inverse[first])
        return floor(min(crossings)) if crossings else None

    def result(logq, status):
        interval = (lower, lower) if logq is None else (
            max(lower, logq - window), min(upper, logq + 1))
        return SearchResult(logq, target, {point: dict(known[point]) for point in sorted(known)},
                            tuple(sorted(complete)), interval, status)

    evaluate_all((lower + upper) // 2 if guess is None else guess)
    step, width, bisect = 1, None, False
    while True:
        unsafe = [point for point in known if safe(point) is False]
        hi = min(unsafe) if unsafe else None
        below = [point for point in known if safe(point) and (hi is None or point < hi)]
        lo = max(below) if below else None
        if hi == lower:
            return result(None, "lower_bound_unsafe")
        if lo is None or (hi is None and lo < upper) or (hi is not None and hi - lo > 1):
            if lo is not None and hi is not None:
                bisect = width is not None and 4 * (hi - lo) > 3 * width
                width = hi - lo
            first, last = lower if lo is None else lo + 1, upper if hi is None else hi - 1
            point = None if bisect else predict()
            speculative = min(batch, 2) if point is not None else 1
            if lo is None or hi is None:
                # Without a bracket, halve the open side, and double the step when stalling.
                if point is None:
                    point = (lower + hi) // 2 if lo is None else (lo + upper + 1) // 2
                forced = hi - step if lo is None else lo + step
                if (point >= forced) if lo is None else (point <= forced):
                    point, step = forced, 2 * step
            elif point is None:
                point = (lo + hi) // 2
            point = max(first, min(last, point))
            # The point after the predicted boundary is expected to be unsafe.
            probe([candidate for candidate in range(point, point + speculative)
                   if candidate <= last or candidate == hi])
            continue
        if lo not in complete:
            evaluate_all(lo)
            continue
        scan = [point for point in range(max(lower, lo - window), lo) if safe(point) is None]
        if scan:
            probe(scan[-batch:])
            continue
        return result(lo, "upper_bound" if hi is None else "boundary")
