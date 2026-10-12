from dataclasses import replace
from decimal import Decimal
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from ckks_estimator import (
    AttackEstimate, DiscreteGaussian, EstimationError, Parameters,
    SparseTernary, Ternary, UnsupportedParameters, evaluate,
)


class Backend:
    name = "synthetic"
    revision = "source-and-dependency-v1"
    cost_model = "classical-operations"
    configuration = {"shape": "test"}
    attacks = ("first", "second")

    def __init__(self, **settings):
        self.calls = []
        self.supported = True
        self.bits = {"first": "Infinity", "second": "127.999999999999999999999999999999999999"}
        self.__dict__.update(settings)

    def supports(self, parameters):
        return self.supported

    def attack(self, parameters, name):
        self.calls.append(name)
        return AttackEstimate(name, self.bits[name])


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "cache.sqlite3"
        self.parameters = Parameters(4096, 2**100, SparseTernary(16, 16), DiscreteGaussian("3.2"))

    def test_default_cache_persists_all_fractional_results_and_reports_unsupported(self):
        first = Backend()
        second = Backend(name="other", bits={"first": "Infinity", "second": "130.5"})
        skipped = Backend(name="sparse-only", supported=False)
        with patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.path.parent)}):
            result = evaluate(self.parameters, [first, second, skipped])
            fresh = Backend()
            repeated = evaluate(self.parameters, [fresh, second, skipped])
        self.assertEqual(repeated, result)
        self.assertTrue(result.complete)
        self.assertEqual(result.security_bits, Decimal(first.bits["second"]))
        self.assertEqual(result.unsupported, ("sparse-only",))
        self.assertEqual([len(e.attacks) for e in result.estimates], [2, 2])
        self.assertEqual([len(b.calls) for b in (first, second, skipped, fresh)], [2, 2, 0, 0])
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
            {"cost_model": "other-model"}, {"configuration": {"shape": "other"}},
        )]
        for parameters, backend in ([(p, Backend()) for p in parameters] +
                                    [(self.parameters, b) for b in backends]):
            with self.subTest(parameters=parameters, backend=backend.__dict__):
                evaluate(parameters, [backend], cache=self.path)
                evaluate(parameters, [backend], cache=self.path)
                self.assertEqual(len(backend.calls), 2)

    def test_attacks_are_cached_separately_and_shared_between_selections(self):
        evaluate(self.parameters, [Backend(attacks=("second",))], cache=self.path)
        both = Backend()
        result = evaluate(self.parameters, [both], cache=self.path)
        self.assertEqual(both.calls, ["first"])
        self.assertEqual([a.attack for a in result.estimates[0].attacks], ["first", "second"])
        unbounded = evaluate(self.parameters, [Backend(attacks=("first",))], cache=self.path)
        self.assertEqual(unbounded.security_bits, Decimal("Infinity"))
        for attacks in ((), ("first", "first")):
            with self.assertRaisesRegex(ValueError, "distinct attacks"):
                evaluate(self.parameters, [Backend(attacks=attacks)], cache=self.path)

    def test_bypass_neither_reads_nor_writes(self):
        with patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.path.parent)}):
            cached = evaluate(self.parameters, [Backend()])
            backend = Backend(bits={"first": "Infinity", "second": "120.25"})
            bypassed = evaluate(self.parameters, [backend], cache=False)
            repeated = evaluate(self.parameters, [backend])
            self.assertEqual(bypassed.security_bits, Decimal("120.25"))
            self.assertEqual(repeated, cached)
            self.assertEqual(len(backend.calls), 2)

    def test_failures_propagate_and_keep_completed_attacks(self):
        for jobs in (1, 2):
            with self.subTest(jobs=jobs):
                cache = self.path.with_name(f"failures-{jobs}.sqlite3")
                good, failing = Backend(), Backend(name="failure")
                with patch.object(failing, "attack", side_effect=EstimationError("attack failed")):
                    with self.assertRaisesRegex(EstimationError, "attack failed"):
                        evaluate(self.parameters, [good, failing], cache=cache, jobs=jobs)
                result = evaluate(self.parameters, [Backend(calls=good.calls), failing],
                                  cache=cache, jobs=jobs)
                self.assertEqual(len(result.estimates), 2)
                self.assertEqual(sorted(good.calls), ["first", "second"])
                self.assertEqual(sorted(failing.calls), ["first", "second"])

    def test_target_stops_at_the_first_attack_below_it(self):
        backend = Backend(attacks=("second", "first"))
        result = evaluate(self.parameters, [backend, Backend(name="later")],
                          cache=self.path, jobs=1, target=128)
        self.assertFalse(result.complete)
        self.assertEqual(backend.calls, ["second"])
        self.assertEqual([(e.estimator, len(e.attacks)) for e in result.estimates], [("synthetic", 1)])
        cached = Backend(name="later")
        self.assertFalse(evaluate(self.parameters, [cached, backend], cache=self.path, target=128).complete)
        self.assertEqual(cached.calls, [])
        safe = evaluate(self.parameters, [Backend()], cache=self.path, jobs=1,
                        target="127.999999999999999999999999999999999999")
        self.assertTrue(safe.complete)

    def test_parallel_refutation_cancels_running_attacks(self):
        started, cancelled = Event(), Event()

        class Slow(Backend):
            name = "slow"
            attacks = ("first",)

            def attack(self, parameters, name):
                started.set()
                if not cancelled.wait(30):
                    raise AssertionError("The running attack was not cancelled.")
                raise EstimationError("cancelled")

            def cancel(self):
                cancelled.set()

        class Refuting(Backend):
            attacks = ("second",)

            def attack(self, parameters, name):
                started.wait(30)
                return super().attack(parameters, name)

        result = evaluate(self.parameters, [Slow(), Refuting()], cache=self.path, jobs=2, target=128)
        self.assertFalse(result.complete)
        self.assertEqual([e.estimator for e in result.estimates], ["synthetic"])
        self.assertTrue(cancelled.is_set())
        complete = evaluate(self.parameters, [Backend(), Backend(name="other")], cache=False, jobs=4)
        self.assertEqual([len(e.attacks) for e in complete.estimates], [2, 2])

    def test_inapplicable_incomparable_and_mismatched_results_are_rejected(self):
        unsupported = Backend(supported=False)
        for backends in ([], [unsupported]):
            with self.assertRaises(UnsupportedParameters):
                evaluate(self.parameters, backends, cache=self.path)
        first, second = Backend(), Backend(cost_model="quantum-operations")
        with self.assertRaisesRegex(ValueError, "same cost model"):
            evaluate(self.parameters, [first, second], cache=self.path)
        self.assertEqual((first.calls, second.calls, unsupported.calls), ([], [], []))
        with patch.object(first, "attack", return_value=AttackEstimate("other", 128)):
            with self.assertRaisesRegex(EstimationError, "mismatched"):
                evaluate(self.parameters, [first], cache=self.path)
        for jobs in (0, 1.5):
            with self.assertRaisesRegex(ValueError, "jobs"):
                evaluate(self.parameters, [first], cache=self.path, jobs=jobs)
        result = evaluate(self.parameters, [first], cache=self.path)
        self.assertEqual(result.estimates[0].parameters, self.parameters)


if __name__ == "__main__":
    unittest.main()
