"""Adapter for malb/lattice-estimator."""

from decimal import Decimal
from functools import partial
import importlib.util
from pathlib import Path
import sys

from ..backend import EstimationError, UnsupportedParameters
from ..installation import backend_path
from ..parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform
from ..results import AttackEstimate, Estimate
from ._source import source_revision


ATTACKS = ("arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid",
           "dual", "dual_hybrid")


class MalbEstimator:
    """Use installed or explicit lattice-estimator sources. Requires Sage."""

    name = "malb/lattice-estimator"

    def __init__(self, path=None, *, attacks=None, cost_model="MATZOV", shape_model="GSA"):
        if attacks is not None:
            attacks = tuple(attacks)
            if not attacks or len(set(attacks)) != len(attacks) or set(attacks) - set(ATTACKS):
                raise ValueError(f"Select distinct attacks from {ATTACKS}.")
        source = (backend_path("malb") if path is None else Path(path).resolve()) / "estimator"
        if not (source / "__init__.py").is_file():
            raise ValueError("Install malb with ckks-estimator-install malb, "
                             "or pass a lattice-estimator checkout path.")

        from sage.all import RR, oo
        from sage.version import version as sage_version
        import fpylll
        import scipy

        self._RR, self._oo = RR, oo
        self.revision = source_revision(
            {"malb": source, "adapter": Path(__file__).parent.parent},
            {"sage": sage_version, "scipy": scipy.__version__, "fpylll": fpylll.__version__},
        )
        module_name = "_ckks_malb_" + self.revision.split(":", 1)[1]
        if module_name not in sys.modules:
            spec = importlib.util.spec_from_file_location(module_name, source / "__init__.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                for key in list(sys.modules):
                    if key == module_name or key.startswith(module_name + "."):
                        del sys.modules[key]
                raise
        self._module = sys.modules[module_name]
        try:
            self._reduction = getattr(self._module.RC, cost_model)
            self._shape = getattr(self._module.Simulator, shape_model)
        except AttributeError as exc:
            raise ValueError("Unknown reduction cost or shape model.") from exc
        if not callable(self._reduction) or not callable(self._shape):
            raise ValueError("Reduction cost and shape models must be callable.")
        self.cost_model = cost_model
        self._shape_name = shape_model
        self._attacks = None if attacks is None else tuple(name for name in ATTACKS if name in attacks)

    @property
    def configuration(self):
        return {"attacks": self._attacks, "shape_model": self._shape_name}

    def supports(self, parameters: Parameters) -> bool:
        return isinstance(parameters, Parameters) and isinstance(
            parameters.error, (DiscreteGaussian, Ternary, Uniform)
        )

    def _distribution(self, distribution, n):
        nd = self._module.ND
        if isinstance(distribution, SparseTernary):
            return nd.SparseTernary(p=distribution.positive, m=distribution.negative, n=n)
        if isinstance(distribution, Ternary):
            return nd.Uniform(-1, 1)
        if isinstance(distribution, Uniform):
            return nd.Uniform(distribution.lower, distribution.upper)
        if isinstance(distribution, DiscreteGaussian):
            return nd.DiscreteGaussian(self._RR(str(distribution.stddev)))
        raise UnsupportedParameters("Unsupported distribution.")

    def _parameters(self, parameters):
        return self._module.LWE.Parameters(
            n=parameters.n, q=parameters.q,
            Xs=self._distribution(parameters.secret, parameters.n),
            Xe=self._distribution(parameters.error, parameters.samples),
            m=self._oo if parameters.samples is None else parameters.samples,
        )

    def _algorithms(self):
        lwe = self._module.LWE
        reduction = {"red_cost_model": self._reduction}
        primal = {**reduction, "red_shape_model": self._shape}
        return {
            "arora-gb": lwe.guess_composition(lwe.arora_gb),
            "bkw": lwe.coded_bkw,
            "usvp": partial(lwe.primal_usvp, **primal),
            "bdd": partial(lwe.primal_bdd, **primal),
            "bdd_hybrid": partial(lwe.primal_hybrid, mitm=False, babai=False, **primal),
            "bdd_mitm_hybrid": partial(lwe.primal_hybrid, mitm=True, babai=True, **primal),
            "dual": partial(lwe.dual, **reduction),
            "dual_hybrid": partial(lwe.dual_hybrid, **reduction),
        }

    def _bits(self, rop):
        from sage.all import RealField

        if rop == self._oo:
            return Decimal("Infinity")
        # Round conversion, logarithm, and decimal rendering downward.
        bits = RealField(128, rnd="RNDD")(rop).log2()
        return Decimal(bits.str(truncate=False))

    def estimate(self, parameters: Parameters) -> Estimate:
        if not self.supports(parameters):
            raise UnsupportedParameters("The malb adapter requires coefficient-wise error distributions.")
        try:
            native = self._parameters(parameters)
        except Exception as exc:
            raise EstimationError(f"Could not construct malb parameters: {exc}") from exc
        if self._attacks is None:
            try:
                results = self._module.LWE.estimate(
                    native, red_cost_model=self._reduction, red_shape_model=self._shape,
                    jobs=1, catch_exceptions=False, quiet=True,
                )
            except Exception as exc:
                raise EstimationError(f"malb estimation failed: {exc}") from exc
        else:
            results = {}
            algorithms = self._algorithms()
            for name in self._attacks:
                try:
                    results[name] = algorithms[name](native.normalize())
                except Exception as exc:
                    raise EstimationError(f"malb attack {name} failed: {exc}") from exc
        try:
            attacks = tuple(AttackEstimate(name, self._bits(cost["rop"]))
                            for name, cost in results.items())
            return Estimate(parameters, self.name, self.revision, self.cost_model,
                            attacks, self.configuration)
        except Exception as exc:
            raise EstimationError(f"Invalid malb result: {exc}") from exc
