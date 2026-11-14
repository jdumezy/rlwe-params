"""RLWE parameter selection and tables, using lattice estimators as backends."""

from .backend import EstimationError, Estimator, UnsupportedParameters
from .api import estimate, max_logq
from .evaluation import evaluate
from .profiles import PROFILES, Profile
from .parameters import DiscreteGaussian, Distribution, Parameters, SparseTernary, Ternary, Uniform
from .results import AttackEstimate, Estimate, Evaluation
from .search import SearchResult, search_logq
from .tables import render_tables, run_table

__all__ = [
    "AttackEstimate", "DiscreteGaussian", "Distribution", "Estimate", "PROFILES", "Profile",
    "EstimationError", "Estimator", "Evaluation", "Parameters", "SparseTernary", "Ternary",
    "Uniform", "UnsupportedParameters", "SearchResult", "estimate", "evaluate", "max_logq",
    "search_logq", "render_tables", "run_table",
]
