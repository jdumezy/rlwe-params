from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ckks_estimator import (
    AttackEstimate, DiscreteGaussian, EstimationError, Parameters,
    SparseTernary, Ternary, UnsupportedParameters, estimate,
)
from ckks_estimator._runtime import Worker, pool
from ckks_estimator._serialization import dumps, loads
from ckks_estimator.cli import main
from ckks_estimator.estimators import MalbEstimator, TabOgEstimator


class Backend:
    name = "synthetic"
    revision = "test-revision"
    cost_model = "test-cost-model"
    configuration = {"shapes": ("test", 1)}
    attacks = ("finite", "infinite")

    def supports(self, parameters):
        return True

    def attack(self, parameters, name):
        return AttackEstimate(name, {"finite": "127.999999999999999999999999999999999999",
                                     "infinite": "Infinity"}[name])


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.parameters = Parameters(256, 2**15, SparseTernary(8, 8), DiscreteGaussian("3.2"))

    def test_public_api_accepts_parameters_and_fields_with_non_sage_backends(self):
        first = estimate(self.parameters, estimators=[Backend()], cache=False)
        second = estimate(n=256, q=2**15, secret=SparseTernary(8, 8),
                          error=DiscreteGaussian("3.2"), estimators=[Backend()], cache=False)
        self.assertEqual(first, second)
        self.assertLess(first.security_bits, Decimal(128))
        with self.assertRaisesRegex(ValueError, "either"):
            estimate(self.parameters, n=512, estimators=[Backend()])

    def test_default_selection_includes_sparse_attacks_and_does_not_hide_missing_backend(self):
        with patch("ckks_estimator.estimators.SageEstimator", return_value=Backend()) as adapter:
            result = estimate(self.parameters, cache=False)
            self.assertEqual(len(result.estimates), 2)
            self.assertEqual([call.args for call in adapter.call_args_list], [("malb",), ("tabog",)])
            self.assertEqual({call.kwargs["cost_model"] for call in adapter.call_args_list}, {"MATZOV"})

        def missing(name, **options):
            if name == "tabog":
                raise ValueError("missing")
            return Backend()

        with patch("ckks_estimator.estimators.SageEstimator", side_effect=missing):
            with self.assertRaisesRegex(ValueError, "missing"):
                estimate(self.parameters, cache=False)
            result = estimate(n=256, q=2**15, secret=Ternary(),
                              error=DiscreteGaussian("3.2"), cache=False)
            self.assertEqual(len(result.estimates), 1)

    def test_wire_preserves_large_moduli_decimal_thresholds_and_configuration_types(self):
        parameters = Parameters(4096, 1 << 20000, SparseTernary(15, 17),
                                DiscreteGaussian("3.200000000000000000000000000000000001"), 8192)
        result = estimate(parameters, estimators=[Backend()], cache=False).estimates[0]
        self.assertEqual(loads(dumps(result)), result)
        self.assertIsInstance(loads(dumps(result)).configuration["shapes"], tuple)
        self.assertEqual(loads(dumps(result)).attacks[1].security_bits, Decimal("Infinity"))

    def test_cli_translates_parameters_and_prints_precise_json(self):
        result = estimate(self.parameters, estimators=[Backend()], cache=False)
        output = io.StringIO()
        with patch("ckks_estimator.cli.estimate", return_value=result) as call, redirect_stdout(output):
            main(["estimate", "--log-n", "8", "--log-q", "15", "--h", "16",
                  "--sigma", "3.2", "--samples", "512", "--no-cache", "--json"])
        supplied = call.call_args.args[0]
        self.assertEqual((supplied.n, supplied.q, supplied.samples), (256, 2**15, 512))
        self.assertEqual(supplied.secret, SparseTernary(8, 8))
        self.assertFalse(call.call_args.kwargs["cache"])
        self.assertEqual(json.loads(output.getvalue())["security_bits"], str(result.security_bits))
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            main(["estimate", "--n", "256", "--q", "32768", "--ternary", "--sigma", "invalid"])
        self.assertEqual(failure.exception.code, 1)

    def test_worker_death_is_reported_and_resources_are_closed(self):
        runtime = Worker((sys.executable, "-c", "raise SystemExit(3)"))
        with self.assertRaises(EstimationError):
            runtime.request("load")
        self.assertIsNone(runtime.process)
        self.assertIsNone(runtime.log)

    def test_inherited_worker_is_rejected_before_acquiring_its_lock(self):
        runtime = Worker((sys.executable,))
        runtime.lock.acquire()
        with patch("ckks_estimator._runtime.os.getpid", return_value=runtime.owner + 1):
            with self.assertRaisesRegex(EstimationError, "child process"):
                runtime.request("load")
        runtime.lock.release()


@unittest.skipUnless(os.environ.get("CKKS_ESTIMATOR_TEST_SAGE"), "Requires installed backend test runtime.")
class RuntimeIntegrationTests(unittest.TestCase):
    def test_ordinary_python_api_cli_cache_and_worker_reuse(self):
        self.assertNotIn("sage.all", sys.modules)
        parameters = Parameters(256, 2**15, SparseTernary(8, 8), DiscreteGaussian("3.2"))
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "estimates.sqlite3"
            result = estimate(parameters, cache=cache)
            self.assertTrue(result.complete)
            self.assertEqual([len(e.attacks) for e in result.estimates], [6, 4])
            self.assertEqual(result, estimate(parameters, cache=False, jobs=1))
            workers = list(pool().idle)
            self.assertGreater(len(workers), 1)
            processes = [runtime.process for runtime in workers]
            original = Worker.request

            def cached_only(runtime, operation, **arguments):
                if operation == "attack":
                    self.fail("A cached estimate reran an attack.")
                return original(runtime, operation, **arguments)

            with patch.object(Worker, "request", cached_only):
                self.assertEqual(estimate(parameters, cache=cache), result)
            self.assertEqual([runtime.process for runtime in workers], processes)
            command = [sys.executable, "-m", "ckks_estimator", "estimate", "--log-n", "8",
                       "--log-q", "15", "--h", "16", "--sigma", "3.2",
                       "--cache", str(cache), "--json"]
            output = subprocess.run(command, check=True, capture_output=True, text=True)
            document = json.loads(output.stdout)
            self.assertEqual(document["security_bits"], str(result.security_bits))
            self.assertEqual([e["revision"] for e in document["estimates"]],
                             [e.revision for e in result.estimates])
            with self.assertRaises(ValueError):
                MalbEstimator(attacks=("does-not-exist",))
            with self.assertRaises(UnsupportedParameters):
                TabOgEstimator().attack(Parameters(256, 2**15, Ternary(), DiscreteGaussian("3.2")),
                                        "primal-without-mitm")
            existing = MalbEstimator()
            self.assertNotIn("arora-gb", existing.attacks)
            self.assertNotIn("bkw", existing.attacks)
            self.assertEqual(MalbEstimator(attacks=("bkw", "usvp")).attacks, ("bkw", "usvp"))
            self.assertTrue(existing.supports(parameters))
            self.assertNotIn("sage.all", sys.modules)
            print(f"Ordinary Python result: {result.security_bits} bits, "
                  f"{sum(len(e.attacks) for e in result.estimates)} attacks.")
            refuted = estimate(parameters, cache=False, target=1000)
            self.assertFalse(result.security_bits >= 1000 or refuted.complete)
            self.assertEqual(estimate(parameters, cache=False), result)
            for runtime in list(pool().idle):
                runtime.close()
            self.assertTrue(existing.supports(parameters))
            for runtime in list(pool().idle):
                runtime.close()


if __name__ == "__main__":
    unittest.main()
