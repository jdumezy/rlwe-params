from decimal import Decimal
import unittest

from ckks_estimator import (
    AttackEstimate, DiscreteGaussian, Estimate, Estimator,
    Parameters, SparseTernary, Ternary, Uniform, UnsupportedParameters,
)


class SingleAttackEstimator:
    """Synthetic single-attack estimator for sparse ternary keys."""

    name = "synthetic"
    revision = "git:0123456789abcdef0123456789abcdef01234567"
    cost_model = "classical-test-operations"
    configuration = {}
    attacks = ("one-attack",)

    def supports(self, parameters):
        return isinstance(parameters.secret, SparseTernary)

    def attack(self, parameters, name):
        if not self.supports(parameters):
            raise UnsupportedParameters("Only sparse ternary secrets are supported.")
        return AttackEstimate(name, "127.7")


class InterfaceTests(unittest.TestCase):
    def parameters(self, secret=None):
        return Parameters(4096, 2**100, secret or SparseTernary(16, 16),
                          DiscreteGaussian("3.2"))

    def test_invalid_distribution_parameters_are_rejected(self):
        for make in (lambda: SparseTernary(-1, 2), lambda: SparseTernary(1.5, 2),
                     lambda: Uniform(2, 1), lambda: Uniform(-1.5, 1),
                     lambda: DiscreteGaussian(0), lambda: DiscreteGaussian("NaN"),
                     lambda: DiscreteGaussian("Infinity")):
            with self.subTest(make=make), self.assertRaises(ValueError):
                make()

    def test_weight_and_exact_integer_parameters_are_validated(self):
        with self.assertRaises(ValueError):
            self.parameters(SparseTernary(4096, 1))
        for n, q in ((0, 17), (4096, 1), (4096, 17.5), (True, 17)):
            with self.subTest(n=n, q=q), self.assertRaises(ValueError):
                Parameters(n, q, Ternary(), DiscreteGaussian("3.2"))
        self.assertEqual(self.parameters().q, 2**100)

    def test_partial_estimator_needs_no_base_class(self):
        backend: Estimator = SingleAttackEstimator()
        parameters = self.parameters()
        self.assertTrue(backend.supports(parameters))
        result = backend.attack(parameters, backend.attacks[0])
        self.assertEqual((result.attack, result.security_bits), ("one-attack", Decimal("127.7")))
        self.assertFalse(backend.supports(self.parameters(Ternary())))
        with self.assertRaises(UnsupportedParameters):
            backend.attack(self.parameters(Ternary()), "one-attack")

    def test_threshold_precision_is_preserved(self):
        value = "127.999999999999999999999999999999999999"
        cost = AttackEstimate("attack", value).security_bits
        self.assertEqual(cost, Decimal(value))
        self.assertLess(cost, Decimal(128))
        self.assertEqual(AttackEstimate("attack", 127.7).security_bits, Decimal("127.7"))

    def test_incomplete_or_ambiguous_results_are_rejected(self):
        attack = AttackEstimate("attack", 128)
        for attacks in ((), (attack, attack)):
            with self.subTest(attacks=attacks), self.assertRaises(ValueError):
                Estimate(self.parameters(), "test", SingleAttackEstimator.revision, "model", attacks)
        for bits in ("NaN", "-Infinity", "-1"):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                AttackEstimate("attack", bits)
        unbounded = Estimate(self.parameters(), "test", SingleAttackEstimator.revision, "model",
                             (AttackEstimate("attack", "Infinity"),))
        self.assertEqual(unbounded.attacks[0].security_bits, Decimal("Infinity"))
        for revision in (None, "", " "):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                Estimate(self.parameters(), "test", revision, "model", (attack,))


if __name__ == "__main__":
    unittest.main()
