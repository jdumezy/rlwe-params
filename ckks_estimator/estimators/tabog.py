"""Adapter for TabOg's rotated primal-hybrid attacks."""

import builtins
from hashlib import sha256
import importlib
from pathlib import Path
import sys
from types import ModuleType

from ..backend import EstimationError, UnsupportedParameters
from ..parameters import Parameters, SparseTernary
from ..results import AttackEstimate, Estimate
from .malb import MalbEstimator
from ._source import source_revision


ATTACKS = {
    "primal-projected-cvp": {"babai": False, "mitm": False},
    "primal-without-mitm": {"babai": True, "mitm": False},
    "primal-mitm-square-root": {"babai": True, "mitm": True, "mitm_heuristic": "square root"},
    "primal-mitm-estimator": {"babai": True, "mitm": True, "mitm_heuristic": "estimator"},
}


def _load_rotated(source, dependency, revision):
    name = "_ckks_tabog_" + sha256(revision.encode()).hexdigest()
    if name in sys.modules:
        return sys.modules[name]
    package = ModuleType("lattice_estimator")
    package.estimator = dependency

    def backend_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "lattice_estimator":
            return package
        prefix = "lattice_estimator.estimator"
        if level == 0 and (name == prefix or name.startswith(prefix + ".")):
            imported = importlib.import_module(dependency.__name__ + name[len(prefix):])
            return imported if fromlist else package
        return builtins.__import__(name, globals, locals, fromlist, level)

    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    # Bind upstream's absolute imports to this checkout's dependency only.
    module.__dict__["__builtins__"] = {**vars(builtins), "__import__": backend_import}
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[name]
        raise
    return module


class TabOgEstimator:
    """Use PrimalHybrid and its lattice_estimator submodule from a TabOg checkout."""

    name = "TabOg/mlwe-hybrids"

    def __init__(self, path, *, attacks=None, cost_model="MATZOV", shape_model="GSA"):
        selected = tuple(ATTACKS) if attacks is None else tuple(attacks)
        if not selected or len(set(selected)) != len(selected) or set(selected) - ATTACKS.keys():
            raise ValueError(f"Select distinct attacks from {tuple(ATTACKS)}.")
        primal = Path(path).resolve() / "PrimalHybrid"
        source = primal / "lwe_rot_primal.py"
        if not source.is_file():
            raise ValueError("path must point to a TabOg/mlwe-hybrids checkout.")
        self._malb = MalbEstimator(primal / "lattice_estimator", cost_model=cost_model,
                                  shape_model=shape_model)
        revision = source_revision({"tabog": source}, {})
        self.revision = f"tabog={revision}|malb={self._malb.revision}"
        self._rotated = _load_rotated(source, self._malb._module, self.revision)
        self.cost_model = cost_model
        self._attacks = tuple(name for name in ATTACKS if name in selected)

    @property
    def configuration(self):
        return {**self._malb.configuration, "attacks": self._attacks}

    def supports(self, parameters: Parameters) -> bool:
        if not self._malb.supports(parameters):
            return False
        if parameters.n < 2 or parameters.n & (parameters.n - 1):
            return False
        if not isinstance(parameters.secret, SparseTernary) or parameters.secret.h == 0:
            return False
        native = self._malb._parameters(parameters).normalize()
        return isinstance(native.Xs, self._malb._module.ND.SparseTernary)

    def estimate(self, parameters: Parameters) -> Estimate:
        if not self.supports(parameters):
            raise UnsupportedParameters(
                "TabOg requires a power-of-two ring and a nonzero sparse ternary secret "
                "that remains sparse ternary after LWE normalization."
            )
        attacks = []
        for name in self._attacks:
            try:
                cost = self._rotated.rot_primal_hybrid(
                    self._malb._parameters(parameters), poly_degree=parameters.n,
                    red_cost_model=self._malb._reduction, red_shape_model=self._malb._shape,
                    **ATTACKS[name],
                )
                attacks.append(AttackEstimate(name, self._malb._bits(cost["rop"])))
            except Exception as exc:
                raise EstimationError(f"TabOg attack {name} failed: {exc}") from exc
        try:
            return Estimate(parameters, self.name, self.revision, self.cost_model,
                            tuple(attacks), self.configuration)
        except ValueError as exc:
            raise EstimationError(f"Invalid TabOg result: {exc}") from exc
