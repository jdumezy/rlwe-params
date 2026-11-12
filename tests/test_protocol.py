from decimal import Decimal
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from rlwe_params import (
    AttackEstimate, DiscreteGaussian, EstimationError, Parameters, Profile, SparseTernary, Ternary,
    Uniform, UnsupportedParameters, estimate, max_logq,
)
from rlwe_params.estimators import ProcessEstimator
from rlwe_params.installation import BACKENDS, Backend
from rlwe_params.protocol import decode_parameters, encode_parameters, raise_error, serve


TOY = Backend((sys.executable, str(Path(__file__).with_name("toy_backend.py"))))


class Adapter:
    name = "adapter"
    revision = "r1"
    cost_model = "MATZOV"
    configuration = {"shape_model": "GSA"}
    attacks = ("first", "second")
    created = 0

    def __init__(self, **options):
        Adapter.created += 1
        self.options = options

    def supports(self, parameters):
        if isinstance(parameters.secret, Uniform):
            raise UnsupportedParameters("Uniform secrets are unsupported.")
        return isinstance(parameters.secret, SparseTernary)

    def attack(self, parameters, name):
        print("estimator output")
        if name == "first":
            return AttackEstimate(name, "127.999999999999999999999999999999999999")
        if name == "second":
            return Decimal("Infinity")
        raise RuntimeError("attack failed")


class ProtocolTests(unittest.TestCase):
    def test_parameters_round_trip_through_plain_json(self):
        for secret in (SparseTernary(15, 17), Ternary(), Uniform(-3, 2),
                       DiscreteGaussian("3.200000000000000000000000000000000001")):
            parameters = Parameters(4096, (1 << 20000) + 1, secret, DiscreteGaussian("3.19"), 8192)
            encoded = json.loads(json.dumps(encode_parameters(parameters)))
            self.assertEqual(decode_parameters(encoded), parameters)
            self.assertIsInstance(encoded["q"], str)
        self.assertIsNone(encode_parameters(Parameters(16, 17, Ternary(), Ternary()))["samples"])
        with self.assertRaisesRegex(ValueError, "Unknown distribution"):
            decode_parameters({**encoded, "secret": {"type": "binary"}})

    def test_serve_answers_requests_and_reports_errors(self):
        parameters = encode_parameters(Parameters(4096, 1 << 100, SparseTernary(16, 16),
                                                  DiscreteGaussian("3.2")))
        uniform = {**parameters, "secret": {"type": "uniform", "lower": -1, "upper": 1}}
        requests = [
            {"op": "describe", "options": {"x": 1}},
            {"op": "supports", "options": {"x": 1}, "parameters": parameters},
            {"op": "attack", "options": {"x": 1}, "parameters": parameters, "attack": "first"},
            {"op": "attack", "options": {"x": 1}, "parameters": parameters, "attack": "second"},
            {"op": "attack", "options": {"x": 1}, "parameters": parameters, "attack": "third"},
            {"op": "supports", "options": {"x": 1}, "parameters": uniform},
            {"op": "unknown", "options": {"x": 1}},
            {"op": "describe", "options": {"x": 2}},
        ]
        output = io.StringIO()
        Adapter.created = 0
        with patch("sys.stderr", io.StringIO()) as errors:
            serve(Adapter, io.StringIO("\n".join(map(json.dumps, requests)) + "\nnot json\n"), output)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[0]["result"], {
            "name": "adapter", "revision": "r1", "cost_model": "MATZOV",
            "configuration": {"shape_model": "GSA"}, "attacks": ["first", "second"]})
        self.assertEqual([response.get("result") for response in responses[1:4]],
                         [True, "127.999999999999999999999999999999999999", "Infinity"])
        self.assertEqual([response.get("error", {}).get("kind") for response in responses[4:]],
                         ["failed", "unsupported", "invalid", None, "invalid"])
        self.assertEqual(Adapter.created, 2)
        self.assertIn("estimator output", errors.getvalue())
        for kind, error in (("unsupported", UnsupportedParameters), ("invalid", ValueError),
                            ("failed", EstimationError), ("other", EstimationError)):
            with self.assertRaises(error):
                raise_error({"kind": kind, "message": "x"})


class ToyBackendTests(unittest.TestCase):
    """A backend that is not Python code for rlwe-params, run as its own process."""

    def setUp(self):
        registry = patch.dict(BACKENDS, {"toy": TOY})
        registry.start()
        self.addCleanup(registry.stop)

    def test_estimates_searches_and_errors_through_the_protocol(self):
        toy = ProcessEstimator("toy")
        self.assertEqual((toy.name, toy.revision, toy.cost_model, toy.attacks),
                         ("toy", "toy-1", "MATZOV", ("primal", "dual")))
        parameters = Parameters(4096, 1 << 100, Ternary(), DiscreteGaussian("3.2"))
        result = estimate(parameters, estimators=[toy], cache=False, jobs=2)
        self.assertEqual(result.security_bits, Decimal("143.36"))
        self.assertEqual(result.estimates[0].attacks[1].security_bits, Decimal("148.36"))
        search = max_logq(n=4096, secret=Ternary(), error=DiscreteGaussian("3.2"), upper=256,
                          estimators=[toy], cache=False, jobs=1)
        self.assertEqual(search.logq, 112)
        with self.assertRaises(UnsupportedParameters):
            toy.supports(Parameters(4096, 1 << 100, Uniform(-1, 1), DiscreteGaussian("3.2")))
        with self.assertRaisesRegex(ValueError, "toy"):
            toy.attack(parameters, "unknown")
        profile = Profile("toy-only", backends=("toy",))
        self.assertEqual([estimator.name for estimator in profile.estimators(parameters)], ["toy"])


if __name__ == "__main__":
    unittest.main()
