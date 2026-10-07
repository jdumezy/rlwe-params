"""Public parameter estimation API."""

from .evaluation import evaluate
from .parameters import Parameters, SparseTernary


def estimate(parameters=None, *, n=None, q=None, secret=None, error=None,
             samples=None, estimators=None, cache=True):
    """Estimate parameters or explicit n, q, secret, error, and sample count.

    By default, use malb and applicable TabOg attacks with the MATZOV cost model.
    Return an Evaluation with security_bits and all per-backend attack results.
    Explicit estimators may implement the Estimator protocol in any runtime.
    """
    if parameters is None:
        parameters = Parameters(n, q, secret, error, samples)
    elif not isinstance(parameters, Parameters):
        raise TypeError("parameters must be a Parameters instance.")
    elif any(value is not None for value in (n, q, secret, error, samples)):
        raise ValueError("Supply either parameters or individual parameter fields.")
    if estimators is None:
        from .estimators import MalbEstimator, TabOgEstimator

        estimators = [MalbEstimator()]
        if (isinstance(parameters.secret, SparseTernary) and parameters.secret.h > 0
                and parameters.n >= 2 and parameters.n & (parameters.n - 1) == 0):
            estimators.append(TabOgEstimator())
    return evaluate(parameters, estimators, cache=cache)
