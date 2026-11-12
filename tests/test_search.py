from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ckks_estimator import (
    AttackEstimate, DiscreteGaussian, EstimationError, SparseTernary, max_logq, search_logq,
)
from ckks_estimator.cli import main


def hyperbola(scale):
    return lambda point: Decimal(scale) / point


class SearchTests(unittest.TestCase):
    def run_curves(self, curves, *, upper=2000, target=128, early=True, **options):
        """Search synthetic attacks. Full evaluations stop at the first attack below the target."""
        requests = []

        def evaluate(batch):
            self.assertLessEqual(len(batch), options.get("batch", 1))
            answers = []
            for point, attacks in batch:
                self.assertTrue(options.get("lower", 15) <= point <= upper)
                requests.append((point, attacks))
                costs = {}
                for name in curves if attacks is None else attacks:
                    costs[name] = curves[name](point)
                    if attacks is None and early and costs[name] < target:
                        break
                answers.append(costs)
            return answers

        result = search_logq(evaluate, upper=upper, target=target, **options)
        self.assertEqual(len(requests), len(set(requests)))
        truth = lambda point: min(curve(point) for curve in curves.values())
        for point in result.certified:
            self.assertEqual(set(result.costs[point]), set(curves))
            self.assertGreaterEqual(truth(point), result.target)
        if result.logq is not None:
            self.assertIn(result.logq, result.certified)
            self.assertEqual(result.security_bits, truth(result.logq))
            start, stop = result.checked_interval
            self.assertTrue(all(result.evaluations[point] >= result.target
                                for point in range(start, result.logq + 1)))
        if result.status == "boundary":
            self.assertLess(result.evaluations[result.logq + 1], result.target)
        full = [point for point, attacks in requests if attacks is None]
        return result, requests, full

    def test_one_point_model_reaches_the_boundary_with_few_evaluations(self):
        curves = {"slow": lambda point: 200, "binding": hyperbola(14000), "other": hyperbola(16000)}
        for guess in (None, 100, 109, 110, 500, 2000):
            with self.subTest(guess=guess):
                result, requests, full = self.run_curves(curves, guess=guess)
                self.assertEqual((result.logq, result.status), (109, "boundary"))
                self.assertEqual(result.q, 1 << 109)
                self.assertEqual(requests[0], (1007 if guess is None else guess, None))
                self.assertLessEqual(len(full), 2)
                self.assertLessEqual(len(requests), 7)
                self.assertTrue(all(attacks in (None, ("binding",)) for _, attacks in requests))
        result, requests, full = self.run_curves(curves, guess=109, window=0)
        self.assertEqual([point for point, _ in requests], [109, 110])

    def test_a_distant_safe_guess_with_another_binding_attack_still_converges(self):
        curves = {"flat": lambda point: 200, "binding": hyperbola(14000)}
        for guess in (15, 30):
            result, requests, full = self.run_curves(curves, guess=guess)
            self.assertEqual(result.logq, 109)
            self.assertLessEqual(len(full), 3)
            self.assertLessEqual(len(requests), 30)

    def test_refuted_certification_follows_the_refuting_attack_and_resumes(self):
        curves = {"first": hyperbola(14000), "late": lambda point: 150 if point < 105 else 100}
        for early in (True, False):
            result, requests, full = self.run_curves(curves, guess=100, early=early)
            self.assertEqual((result.logq, result.certified), (104, (100, 104)))
            self.assertEqual(full, [100, 109, 104])
            self.assertLess(result.costs[105]["late"], 128)
            self.assertEqual(requests[requests.index((109, None)) + 1][1], ("late",))

    def test_window_moves_the_boundary_below_a_nearby_dip(self):
        dip = lambda point: Decimal(240000) / point - (2 if point == 1873 else 0)
        result, requests, _ = self.run_curves({"attack": dip}, upper=4000, guess=1750)
        self.assertEqual(Decimal(240000) // 128, 1875)
        self.assertEqual(result.logq, 1872)
        self.assertEqual(result.checked_interval, (1870, 1873))
        ignored, _, _ = self.run_curves({"attack": dip}, upper=4000, guess=1750, window=0)
        self.assertEqual(ignored.logq, 1875)

    def test_linear_curves_and_both_bracketing_directions(self):
        for boundary in (1738, 1762):
            result, requests, full = self.run_curves(
                {"attack": lambda point: max(0, 128 + boundary - point)}, guess=1750)
            self.assertEqual(result.logq, boundary)
            self.assertLessEqual(len(requests), 14)
        result, requests, _ = self.run_curves({"attack": lambda point: max(0, 270 - point)}, upper=100000)
        self.assertEqual(result.logq, 142)
        self.assertLessEqual(len(requests), 30)

    def test_batches_request_the_point_after_the_predicted_boundary(self):
        curves = {"binding": hyperbola(14000)}
        result, requests, _ = self.run_curves(curves, guess=100, batch=2)
        self.assertEqual(result.logq, 109)
        self.assertEqual([point for point, _ in requests], [100, 109, 110, 109, 107, 108])

    def test_search_limits(self):
        safe, requests, full = self.run_curves({"attack": lambda point: 500}, guess=1750)
        self.assertEqual((safe.logq, safe.status, full), (2000, "upper_bound", [1750, 2000]))
        unsafe, requests, full = self.run_curves({"attack": lambda point: 5}, guess=1750)
        self.assertEqual((unsafe.logq, unsafe.status, unsafe.security_bits), (None, "lower_bound_unsafe", None))
        self.assertEqual(unsafe.checked_interval, (15, 15))
        edge, _, _ = self.run_curves({"attack": hyperbola(14000)}, lower=109, upper=110)
        self.assertEqual(edge.logq, 109)
        exact, _, _ = self.run_curves({"attack": lambda point: Decimal(128) if point <= 40 else Decimal("127.999999999999999999999999999999999999")}, guess=50)
        self.assertEqual(exact.logq, 40)

    def test_invalid_arguments_and_results_are_rejected(self):
        evaluate = lambda batch: [{"attack": 128} for _ in batch]
        for options in ({"upper": 10}, {"upper": 100, "lower": 0}, {"upper": 100, "guess": 101},
                        {"upper": 100, "window": -1}, {"upper": 100, "batch": 0},
                        {"upper": 100, "target": 0}, {"upper": 100, "target": "NaN"},
                        {"upper": 100.5}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                search_logq(evaluate, **options)
        for answer in ({}, {"attack": "NaN"}, {"attack": -1}):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                search_logq(lambda batch: [answer], upper=100)
        with self.assertRaisesRegex(ValueError, "omitted"):
            search_logq(lambda batch: [{"attack": 200} if batch[0][1] is None else {}], upper=100)


class Backend:
    revision = "test-revision"
    cost_model = "test-cost-model"
    configuration = {}

    def __init__(self, name, curves):
        self.name = name
        self.curves = curves
        self.attacks = tuple(curves)
        self.calls = []

    def supports(self, parameters):
        return True

    def attack(self, parameters, name):
        point = parameters.q.bit_length() - 1
        self.calls.append((point, name))
        return AttackEstimate(name, self.curves[name](point))


class MaxLogqTests(unittest.TestCase):
    options = {"n": 4096, "secret": SparseTernary(16, 16), "error": DiscreteGaussian("3.2"), "upper": 2000}

    def test_only_binding_attacks_run_away_from_certified_points(self):
        for jobs in (1, 4):
            with self.subTest(jobs=jobs), tempfile.TemporaryDirectory() as directory:
                cache = Path(directory) / "estimates.sqlite3"
                first = Backend("first", {"binding": hyperbola(14000), "slow": lambda point: 300})
                second = Backend("second", {"other": hyperbola(20000)})
                events = []
                result = max_logq(estimators=[first, second], cache=cache, jobs=jobs,
                                  progress=lambda *event: events.append(event), **self.options)
                self.assertEqual((result.logq, result.status), (109, "boundary"))
                self.assertEqual(set(result.costs[109]),
                                 {"first / binding", "first / slow", "second / other"})
                self.assertEqual(sorted(point for point, name in first.calls if name == "slow"),
                                 sorted(result.certified))
                self.assertEqual(len(first.calls), len(set(first.calls)))
                self.assertEqual({point for point, _, full in events if full}, set(result.certified))
                self.assertEqual(events[0][0], 108)
                repeated = Backend("first", first.curves)
                self.assertEqual(max_logq(estimators=[repeated, second], cache=cache, jobs=jobs,
                                          **self.options), result)
                self.assertEqual(repeated.calls, [])

    def test_backend_failures_and_duplicate_names_propagate(self):
        backend = Backend("first", {"binding": hyperbola(14000)})
        with patch.object(backend, "attack", side_effect=EstimationError("attack failed")):
            with self.assertRaisesRegex(EstimationError, "attack failed"):
                max_logq(estimators=[backend], cache=False, **self.options)
        with self.assertRaisesRegex(ValueError, "distinct"):
            max_logq(estimators=[backend, Backend("first", backend.curves)], cache=False, **self.options)

    def test_cli_search_reports_the_certified_boundary(self):
        backend = Backend("first", {"binding": hyperbola(14000)})
        result = max_logq(estimators=[backend], cache=False, guess=109, **self.options)
        arguments = ["search", "--log-n", "12", "--h", "32", "--sigma", "3.2",
                     "--upper", "2000", "--target", "128", "--guess", "100", "--no-cache"]
        output = io.StringIO()
        with patch("ckks_estimator.cli.max_logq", return_value=result) as call, redirect_stdout(output):
            main([*arguments, "--json"])
        self.assertEqual((call.call_args.kwargs["n"], call.call_args.kwargs["guess"]), (4096, 100))
        self.assertFalse(call.call_args.kwargs["cache"])
        document = json.loads(output.getvalue())
        self.assertEqual((document["logq"], document["status"], document["certified"]),
                         (109, "boundary", [109]))
        self.assertEqual(document["costs"]["109"], {"first / binding": str(result.security_bits)})
        output, errors = io.StringIO(), io.StringIO()
        real = max_logq
        with patch("ckks_estimator.cli.max_logq",
                   side_effect=lambda **options: real(**{**options, "estimators": [backend]})):
            with redirect_stdout(output), redirect_stderr(errors):
                main([*arguments, "--details", "--progress"])
        self.assertIn("logq=109 (q=2**109)", output.getvalue())
        self.assertIn("logq=109 (all attacks) / first / binding", output.getvalue())
        self.assertIn("logq=110: 127.27 bits (first / binding), binding attack", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
