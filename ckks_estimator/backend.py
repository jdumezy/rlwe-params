"""The interface implemented by full and partial estimators."""

from typing import Protocol

from .parameters import Parameters
from .results import Estimate


class UnsupportedParameters(ValueError):
    """The estimator cannot evaluate this parameter description."""


class EstimationError(RuntimeError):
    """Evaluation failed to produce a complete result for the requested attacks."""


class Estimator(Protocol):
    """Interface for a configured estimator."""

    name: str
    revision: str
    cost_model: str

    def supports(self, parameters: Parameters) -> bool:
        """Check applicability without running estimation."""
        ...

    def estimate(self, parameters: Parameters) -> Estimate:
        """Evaluate all attacks selected in this estimator's configuration.

        Raise UnsupportedParameters for unsupported inputs and EstimationError
        for failed evaluations.
        """
        ...
