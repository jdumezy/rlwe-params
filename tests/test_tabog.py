import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from ckks_estimator import (
    DiscreteGaussian, EstimationError, Parameters, SparseTernary, Ternary,
    UnsupportedParameters,
)
from ckks_estimator.estimators._tabog import TabOgEstimator


TABOG_PATH = os.environ.get("TABOG_ESTIMATOR_PATH")


@unittest.skipUnless(TABOG_PATH and importlib.util.find_spec("sage"),
                     "Requires Sage and TABOG_ESTIMATOR_PATH.")
class TabOgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = TabOgEstimator(TABOG_PATH)

    def parameters(self, n=256, secret=None, error=None):
        return Parameters(n, 2**15, secret or SparseTernary(8, 8),
                          error or DiscreteGaussian("3.2"))

    def test_matches_direct_four_attack_calls(self):
        from sage.all import RealField

        primal = str(Path(TABOG_PATH).resolve() / "PrimalHybrid")
        with patch.object(sys, "path", [primal, *sys.path]):
            from lattice_estimator.estimator import LWE, ND, RC, Simulator
            spec = importlib.util.spec_from_file_location("tabog_reference", Path(primal) / "lwe_rot_primal.py")
            reference = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(reference)
        native = LWE.Parameters(n=256, q=2**15, Xs=ND.SparseTernary(8, 8),
                                Xe=ND.DiscreteGaussian("3.2"))
        expected = (
            ("primal-projected-cvp", {"babai": False, "mitm": False}),
            ("primal-without-mitm", {"babai": True, "mitm": False}),
            ("primal-mitm-square-root", {"babai": True, "mitm": True, "mitm_heuristic": "square root"}),
            ("primal-mitm-estimator", {"babai": True, "mitm": True, "mitm_heuristic": "estimator"}),
        )
        result = self.backend.estimate(self.parameters())
        self.assertEqual(tuple(attack.attack for attack in result.attacks), tuple(name for name, _ in expected))
        for attack, (_, options) in zip(result.attacks, expected):
            direct = reference.rot_primal_hybrid(native, poly_degree=256, red_cost_model=RC.MATZOV,
                                                 red_shape_model=Simulator.GSA, **options)
            bits = RealField(128, rnd="RNDD")(direct["rop"]).log2()
            self.assertEqual(str(attack.security_bits), bits.str(truncate=False))
        self.assertEqual(result.revision, self.backend.revision)
        self.assertEqual(result.configuration["attacks"], tuple(name for name, _ in expected))

    def test_applicability_selection_and_failure(self):
        self.assertTrue(self.backend.supports(self.parameters()))
        for parameters in (self.parameters(n=255), self.parameters(secret=Ternary()),
                           self.parameters(secret=SparseTernary(0, 0)),
                           self.parameters(error=DiscreteGaussian("0.01"))):
            with self.subTest(parameters=parameters):
                self.assertFalse(self.backend.supports(parameters))
                with self.assertRaises(UnsupportedParameters):
                    self.backend.estimate(parameters)
        backend = TabOgEstimator(TABOG_PATH, attacks=("primal-mitm-estimator",))
        with patch.object(backend._rotated, "rot_primal_hybrid", return_value={"rop": 2**127}) as attack:
            result = backend.estimate(self.parameters())
            self.assertEqual(len(result.attacks), 1)
            attack.assert_called_once()
            self.assertEqual(attack.call_args.kwargs["poly_degree"], 256)
            self.assertEqual(attack.call_args.kwargs["mitm_heuristic"], "estimator")
            attack.side_effect = RuntimeError("failed")
            with self.assertRaisesRegex(EstimationError, "primal-mitm-estimator failed"):
                backend.estimate(self.parameters())

    def test_revision_and_imports_follow_the_pinned_dependency(self):
        original = Path(TABOG_PATH).resolve() / "PrimalHybrid"
        with tempfile.TemporaryDirectory() as directory:
            primal = Path(directory) / "PrimalHybrid"
            primal.mkdir()
            shutil.copyfile(original / "lwe_rot_primal.py", primal / "lwe_rot_primal.py")
            shutil.copytree(original / "lattice_estimator" / "estimator",
                            primal / "lattice_estimator" / "estimator",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            configuration = primal / "lattice_estimator" / "estimator" / "conf.py"
            marker = self.backend._rotated.max_beta_global - 1
            with configuration.open("a") as stream:
                stream.write(f"\nmax_beta = {marker}\n")
            sentinel = ModuleType("lattice_estimator")
            with patch.dict(sys.modules, {"lattice_estimator": sentinel}):
                modified = TabOgEstimator(directory)
                self.assertIs(sys.modules["lattice_estimator"], sentinel)
            self.assertNotEqual(modified.revision, self.backend.revision)
            self.assertEqual(modified._rotated.max_beta_global, marker)
            self.assertNotEqual(self.backend._rotated.max_beta_global, marker)
            self.assertIs(modified._rotated.LWEParameters, modified._malb._module.LWE.Parameters)


if __name__ == "__main__":
    unittest.main()
