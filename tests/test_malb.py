from decimal import Decimal
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from ckks_estimator import (
    DiscreteGaussian, EstimationError, Parameters, SparseTernary, Ternary,
    Uniform, UnsupportedParameters,
)
from ckks_estimator.estimators._malb import ATTACKS, DEFAULT_ATTACKS, MalbEstimator
from ckks_estimator.estimators._source import source_revision


class SourceTests(unittest.TestCase):
    def test_revision_tracks_code_and_runtime_not_checkout_location(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "original"
            source.mkdir()
            code = source / "attack.py"
            code.write_text("cost = 128\n")
            runtime = {"sage": "test-version"}
            original = source_revision({"backend": source}, runtime)
            clone = Path(directory) / "clone"
            shutil.copytree(source, clone)
            (clone / "notes.txt").write_text("Notes.\n")
            self.assertEqual(original, source_revision({"backend": clone}, runtime))
            code.write_text("cost = 127\n")
            self.assertNotEqual(original, source_revision({"backend": source}, runtime))
            self.assertNotEqual(original, source_revision({"backend": clone}, {"sage": "changed"}))


MALB_PATH = os.environ.get("MALB_ESTIMATOR_PATH")


@unittest.skipUnless(MALB_PATH and importlib.util.find_spec("sage"),
                     "Requires Sage and MALB_ESTIMATOR_PATH.")
class MalbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = MalbEstimator(MALB_PATH, attacks=ATTACKS)

    def parameters(self, secret=None, samples=None):
        return Parameters(128, 3329, secret or Ternary(), DiscreteGaussian("3.2"), samples)

    def test_parameter_translation(self):
        nd = self.backend._module.ND
        distributions = (
            (SparseTernary(7, 13), nd.SparseTernary(7, 13, 128)),
            (Ternary(), nd.Uniform(-1, 1, n=128)),
            (Uniform(-8, 8), nd.Uniform(-8, 8, n=128)),
            (DiscreteGaussian("3.2"), nd.DiscreteGaussian("3.2").resize(128)),
        )
        for secret, expected in distributions:
            with self.subTest(secret=secret):
                native = self.backend._parameters(self.parameters(secret, samples=256))
                self.assertEqual(native.Xs, expected)
                self.assertEqual((native.n, native.q, native.m), (128, 3329, 256))
                self.assertEqual(native.Xe.stddev, self.backend._RR("3.2"))
        self.assertEqual(self.backend._parameters(self.parameters()).m, self.backend._oo)
        unsupported = Parameters(128, 3329, Ternary(), SparseTernary(7, 13))
        self.assertFalse(self.backend.supports(unsupported))
        with self.assertRaises(UnsupportedParameters):
            self.backend.attack(unsupported, "usvp")

    def test_matches_native_all_attack_estimate(self):
        from sage.all import RR

        parameters = self.parameters()
        result = [self.backend.attack(parameters, name) for name in self.backend.attacks]
        module = self.backend._module
        direct = module.LWE.estimate(
            module.LWE.Parameters(n=128, q=3329, Xs=module.ND.Uniform(-1, 1),
                                  Xe=module.ND.DiscreteGaussian("3.2")),
            red_cost_model=module.RC.MATZOV, red_shape_model=module.Simulator.GSA,
            catch_exceptions=False, quiet=True,
        )
        self.assertEqual({attack.attack for attack in result}, set(direct))
        self.assertEqual(MalbEstimator(MALB_PATH).attacks, DEFAULT_ATTACKS)
        self.assertEqual(set(ATTACKS) - set(DEFAULT_ATTACKS), {"arora-gb", "bkw"})
        self.assertEqual(MalbEstimator(MALB_PATH).revision, self.backend.revision)
        for attack in result:
            rop = direct[attack.attack]["rop"]
            if rop == self.backend._oo:
                self.assertEqual(attack.security_bits, Decimal("Infinity"))
            else:
                self.assertEqual(RR(str(attack.security_bits)), RR(rop).log2())
        self.assertEqual(self.backend.configuration, {"shape_model": "GSA"})

    def test_cost_conversion_does_not_cross_threshold(self):
        from sage.all import RR

        for rop, target in (((1 << 128) - 1, 128),
                            (RR(2)**128 - RR(2)**75, 128),
                            ((1 << 1024) - 1, 1024)):
            with self.subTest(rop=rop):
                self.assertLess(self.backend._bits(rop), Decimal(target))
        self.assertEqual(self.backend._bits(1 << 128), Decimal(128))

    def test_selected_attacks_preserve_infinity_and_propagate_failures(self):
        backend = MalbEstimator(MALB_PATH, attacks=("usvp", "bdd_mitm_hybrid"))
        finite = Mock(return_value={"rop": backend._RR(2)**127})
        unbounded = Mock(return_value={"rop": backend._oo})
        unused = Mock(side_effect=AssertionError("Unselected attack ran."))
        algorithms = {"usvp": finite, "bdd_mitm_hybrid": unbounded, "bdd": unused}
        with patch.object(backend, "_algorithms", return_value=algorithms):
            self.assertEqual([backend.attack(self.parameters(), name).security_bits
                              for name in backend.attacks], [Decimal(127), Decimal("Infinity")])
            with self.assertRaisesRegex(ValueError, "not selected"):
                backend.attack(self.parameters(), "bdd")
            unused.assert_not_called()
            unbounded.side_effect = RuntimeError("attack failed")
            with self.assertRaisesRegex(EstimationError, "bdd_mitm_hybrid failed"):
                backend.attack(self.parameters(), "bdd_mitm_hybrid")


if __name__ == "__main__":
    unittest.main()
