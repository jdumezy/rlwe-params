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

from rlwe_params import (
    AttackEstimate, DiscreteGaussian, EstimationError, Parameters,
    SparseTernary, Ternary, Uniform, UnsupportedParameters, estimate,
)
from rlwe_params._runtime import Worker, backend_command, pool
from rlwe_params.cli import main
from rlwe_params.estimators import MalbEstimator, TabOgEstimator


class Backend:
    name = "synthetic"
    revision = "test-revision"
    cost_model = "test-cost-model"
    configuration = {"shapes": ["test", 1]}
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
        with patch("rlwe_params.estimators.ProcessEstimator", return_value=Backend()) as adapter:
            result = estimate(self.parameters, cache=False)
            self.assertEqual(len(result.estimates), 2)
            self.assertEqual([call.args for call in adapter.call_args_list], [("malb",), ("tabog",)])
            self.assertEqual({call.kwargs["cost_model"] for call in adapter.call_args_list}, {"MATZOV"})

        def missing(name, **options):
            if name == "tabog":
                raise ValueError("missing")
            return Backend()

        with patch("rlwe_params.estimators.ProcessEstimator", side_effect=missing):
            with self.assertRaisesRegex(ValueError, "missing"):
                estimate(self.parameters, cache=False)
            result = estimate(n=256, q=2**15, secret=Ternary(),
                              error=DiscreteGaussian("3.2"), cache=False)
            self.assertEqual(len(result.estimates), 1)

    def test_cli_translates_parameters_and_prints_precise_json(self):
        result = estimate(self.parameters, estimators=[Backend()], cache=False)
        output = io.StringIO()
        with patch("rlwe_params.cli.estimate", return_value=result) as call, redirect_stdout(output):
            main(["estimate", "--log-n", "8", "--log-q", "15", "--h", "16",
                  "--sigma", "3.2", "--samples", "512", "--no-cache", "--json"])
        supplied = call.call_args.args[0]
        self.assertEqual((supplied.n, supplied.q, supplied.samples), (256, 2**15, 512))
        self.assertEqual(supplied.secret, SparseTernary(8, 8))
        self.assertFalse(call.call_args.kwargs["cache"])
        self.assertEqual(json.loads(output.getvalue())["security_bits"], str(result.security_bits))
        for flags, expected in ((["--sparse-binary", "16"], SparseTernary(16, 0)),
                                (["--binary"], Uniform(0, 1))):
            with patch("rlwe_params.cli.estimate", return_value=result) as call, redirect_stdout(io.StringIO()):
                main(["estimate", "--log-n", "8", "--log-q", "15", *flags, "--no-cache"])
            self.assertEqual(call.call_args.args[0].secret, expected)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            main(["estimate", "--n", "256", "--q", "32768", "--ternary", "--sigma", "invalid"])
        self.assertEqual(failure.exception.code, 1)

    def test_worker_death_is_reported_and_resources_are_closed(self):
        runtime = Worker((sys.executable, "-c", "raise SystemExit(3)"))
        with self.assertRaises(EstimationError):
            runtime.request({"op": "describe"})
        self.assertIsNone(runtime.process)
        self.assertIsNone(runtime.log)

    def test_inherited_worker_is_rejected_before_acquiring_its_lock(self):
        runtime = Worker((sys.executable,))
        runtime.lock.acquire()
        with patch("rlwe_params._runtime.os.getpid", return_value=runtime.owner + 1):
            with self.assertRaisesRegex(EstimationError, "child process"):
                runtime.request({"op": "describe"})
        runtime.lock.release()


@unittest.skipUnless(os.environ.get("RLWE_PARAMS_TEST_SAGE"), "Requires installed backend test runtime.")
class RuntimeIntegrationTests(unittest.TestCase):
    def test_ordinary_python_api_cli_cache_and_worker_reuse(self):
        self.assertNotIn("sage.all", sys.modules)
        parameters = Parameters(256, 2**15, SparseTernary(8, 8), DiscreteGaussian("3.2"))
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "estimates.sqlite3"
            result = estimate(parameters, cache=cache)
            self.assertTrue(result.complete)
            self.assertEqual([len(e.attacks) for e in result.estimates], [7, 4])
            self.assertEqual(result, estimate(parameters, cache=False, jobs=1))
            workers = list(pool(backend_command("malb")).idle)
            self.assertGreater(len(workers), 1)
            processes = [runtime.process for runtime in workers]
            original = Worker.request

            def cached_only(runtime, message):
                if message["op"] == "attack":
                    self.fail("A cached estimate reran an attack.")
                return original(runtime, message)

            with patch.object(Worker, "request", cached_only):
                self.assertEqual(estimate(parameters, cache=cache), result)
            self.assertEqual([runtime.process for runtime in workers], processes)
            command = [sys.executable, "-m", "rlwe_params", "estimate", "--log-n", "8",
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
            for runtime in list(pool(backend_command("malb")).idle):
                runtime.close()
            self.assertTrue(existing.supports(parameters))
            for runtime in list(pool(backend_command("malb")).idle):
                runtime.close()


if __name__ == "__main__":
    unittest.main()
