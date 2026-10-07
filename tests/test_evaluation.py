from dataclasses import replace
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ckks_estimator import (
    AttackEstimate, DiscreteGaussian, Estimate, EstimationError, Parameters,
    SparseTernary, Ternary, UnsupportedParameters, evaluate,
)


class Backend:
    name = "synthetic"
    revision = "source-and-dependency-v1"
    cost_model = "classical-operations"
    configuration = {"attacks": ("first", "second"), "shape": "test"}

    def __init__(self, **settings):
        self.calls = 0
        self.supported = True
        self.bits = "127.999999999999999999999999999999999999"
        self.__dict__.update(settings)

    def supports(self, parameters):
        return self.supported

    def estimate(self, parameters):
        self.calls += 1
        return Estimate(parameters, self.name, self.revision, self.cost_model,
                        (AttackEstimate("first", "Infinity"), AttackEstimate("second", self.bits)),
                        self.configuration)


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "cache.sqlite3"
        self.parameters = Parameters(4096, 2**100, SparseTernary(16, 16), DiscreteGaussian("3.2"))

    def test_default_cache_persists_all_fractional_results_and_reports_unsupported(self):
        first, second = Backend(), Backend(name="other", bits="130.5")
        skipped = Backend(name="sparse-only", supported=False)
        with patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.path.parent)}):
            result = evaluate(self.parameters, [first, second, skipped])
            fresh = Backend()
            repeated = evaluate(self.parameters, [fresh, second, skipped])
        self.assertEqual(repeated, result)
        self.assertEqual(result.security_bits, Decimal(first.bits))
        self.assertEqual(result.unsupported, ("sparse-only",))
        self.assertEqual([len(e.attacks) for e in result.estimates], [2, 2])
        self.assertEqual((first.calls, second.calls, skipped.calls, fresh.calls), (1, 1, 0, 0))
        self.assertTrue((self.path.parent / "ckks-estimator" / "estimates.sqlite3").is_file())

    def test_cache_invalidates_parameters_sources_models_and_configuration(self):
        evaluate(self.parameters, [Backend()], cache=self.path)
        parameters = [replace(self.parameters, **change) for change in (
            {"n": 8192}, {"q": self.parameters.q + 1}, {"samples": 4096},
            {"secret": SparseTernary(15, 17)}, {"secret": Ternary()},
            {"error": DiscreteGaussian("3.200000000000000000000000000000000001")},
        )]
        backends = [Backend(**change) for change in (
            {"name": "other"}, {"revision": "source-and-dependency-v2"},
            {"cost_model": "other-model"}, {"configuration": {"attacks": ("first",)}},
        )]
        for parameters, backend in ([(p, Backend()) for p in parameters] +
                                    [(self.parameters, b) for b in backends]):
            with self.subTest(parameters=parameters, backend=backend.__dict__):
                evaluate(parameters, [backend], cache=self.path)
                evaluate(parameters, [backend], cache=self.path)
                self.assertEqual(backend.calls, 1)
        reordered = Backend(configuration={"shape": "test", "attacks": ("first", "second")})
        evaluate(self.parameters, [reordered], cache=self.path)
        self.assertEqual(reordered.calls, 0)

    def test_bypass_neither_reads_nor_writes(self):
        with patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.path.parent)}):
            cached = evaluate(self.parameters, [Backend()])
            backend = Backend(bits="120.25")
            bypassed = evaluate(self.parameters, [backend], cache=False)
            repeated = evaluate(self.parameters, [backend])
            self.assertEqual(bypassed.security_bits, Decimal("120.25"))
            self.assertEqual(repeated, cached)
            self.assertEqual(backend.calls, 1)

    def test_failures_propagate_without_caching_incomplete_results(self):
        good, failing = Backend(), Backend(name="failure")
        with patch.object(failing, "estimate", side_effect=EstimationError("attack failed")) as call:
            for _ in range(2):
                with self.assertRaisesRegex(EstimationError, "attack failed"):
                    evaluate(self.parameters, [good, failing], cache=self.path)
            self.assertEqual(call.call_count, 2)
        self.assertEqual(good.calls, 1)
        result = evaluate(self.parameters, [good, failing], cache=self.path)
        self.assertEqual(len(result.estimates), 2)
        self.assertEqual(failing.calls, 1)

    def test_inapplicable_incomparable_and_mismatched_results_are_rejected(self):
        unsupported = Backend(supported=False)
        for backends in ([], [unsupported]):
            with self.assertRaises(UnsupportedParameters):
                evaluate(self.parameters, backends, cache=self.path)
        first, second = Backend(), Backend(cost_model="quantum-operations")
        with self.assertRaisesRegex(ValueError, "same cost model"):
            evaluate(self.parameters, [first, second], cache=self.path)
        self.assertEqual((first.calls, second.calls, unsupported.calls), (0, 0, 0))
        wrong = first.estimate(replace(self.parameters, q=self.parameters.q + 1))
        with patch.object(first, "estimate", return_value=wrong):
            with self.assertRaisesRegex(EstimationError, "provenance"):
                evaluate(self.parameters, [first], cache=self.path)
        result = evaluate(self.parameters, [first], cache=self.path)
        self.assertEqual(result.estimates[0].parameters, self.parameters)
        self.assertEqual(first.calls, 2)


if __name__ == "__main__":
    unittest.main()
