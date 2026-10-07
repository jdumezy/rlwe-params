"""Normalized attack costs and their provenance."""

from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple

from .parameters import Parameters


@dataclass(frozen=True)
class AttackEstimate:
    """Base-2 logarithm of attack cost in the enclosing estimate's cost model."""

    attack: str
    security_bits: Decimal

    def __post_init__(self) -> None:
        value = Decimal(str(self.security_bits))
        if not self.attack or not value.is_finite() or value < 0:
            raise ValueError("An attack needs a name and a finite, nonnegative cost.")
        object.__setattr__(self, "security_bits", value)


@dataclass(frozen=True)
class Estimate:
    """Completed costs for the listed attacks.

    cost_model specifies the work metric and classical or quantum convention.
    revision is an immutable source reference, such as a commit or content hash.
    It must identify adapter and dependency changes, including local edits.
    """

    parameters: Parameters
    estimator: str
    revision: str
    cost_model: str
    attacks: Tuple[AttackEstimate, ...]

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.estimator, self.revision, self.cost_model)):
            raise ValueError("Estimator, source revision, and cost model are required.")
        attacks = tuple(self.attacks)
        if not attacks or not all(isinstance(attack, AttackEstimate) for attack in attacks):
            raise ValueError("An estimate needs at least one completed attack.")
        if len({attack.attack for attack in attacks}) != len(attacks):
            raise ValueError("Attack names must be unique within an estimate.")
        object.__setattr__(self, "attacks", attacks)
