"""The interface implemented by full and partial estimators."""

from typing import Mapping, Protocol, Tuple

from .parameters import Parameters
from .results import AttackEstimate


class UnsupportedParameters(ValueError):
    """The estimator cannot evaluate this parameter description."""


class EstimationError(RuntimeError):
    """Evaluation failed to produce a result for the requested attack."""


class Estimator(Protocol):
    """Interface for a configured estimator.

    attacks names the selected attacks, each evaluated and cached separately.
    configuration holds every other setting that affects a cost, as JSON.
    cost_model must identify comparable work units.

    Parallel evaluation calls attack() from several threads. An estimator may
    define cancel() to abandon its running attacks, which then raise.
    """

    name: str
    revision: str
    cost_model: str
    configuration: Mapping[str, object]
    attacks: Tuple[str, ...]

    def supports(self, parameters: Parameters) -> bool:
        """Check applicability without running estimation."""
        ...

    def attack(self, parameters: Parameters, name: str) -> AttackEstimate:
        """Evaluate one selected attack.

        Raise UnsupportedParameters for unsupported inputs and EstimationError
        for failed evaluations. Positive infinity is a completed result.
        """
        ...
