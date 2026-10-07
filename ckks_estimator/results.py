"""Normalized attack costs and their provenance."""

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Mapping, Tuple

from .parameters import Parameters


@dataclass(frozen=True)
class AttackEstimate:
    """Log2 attack cost. Positive infinity denotes no finite modeled cost."""

    attack: str
    security_bits: Decimal

    def __post_init__(self) -> None:
        value = Decimal(str(self.security_bits))
        if not self.attack or value.is_nan() or value < 0:
            raise ValueError("An attack needs a name and a nonnegative cost.")
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
    configuration: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.estimator, self.revision, self.cost_model)):
            raise ValueError("Estimator, source revision, and cost model are required.")
        attacks = tuple(self.attacks)
        if not attacks or not all(isinstance(attack, AttackEstimate) for attack in attacks):
            raise ValueError("An estimate needs at least one completed attack.")
        if len({attack.attack for attack in attacks}) != len(attacks):
            raise ValueError("Attack names must be unique within an estimate.")
        if not any(attack.security_bits.is_finite() for attack in attacks):
            raise ValueError("No attack produced a finite cost.")
        object.__setattr__(self, "attacks", attacks)
        object.__setattr__(self, "configuration", dict(self.configuration))
