"""Backend-independent descriptions of CKKS security parameters."""

from dataclasses import dataclass
from decimal import Decimal
from typing import Union


def _integer(name: str, value: int, minimum: int) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}.")


@dataclass(frozen=True)
class SparseTernary:
    """Uniform vectors with exactly these counts of +1 and -1 coefficients."""

    positive: int
    negative: int

    def __post_init__(self) -> None:
        _integer("positive", self.positive, 0)
        _integer("negative", self.negative, 0)

    @property
    def h(self) -> int:
        return self.positive + self.negative


@dataclass(frozen=True)
class Ternary:
    """Independent coefficients uniform on {-1, 0, 1}."""


@dataclass(frozen=True)
class Uniform:
    """Independent coefficients uniform on the inclusive integer interval."""

    lower: int
    upper: int

    def __post_init__(self) -> None:
        if type(self.lower) is not int or type(self.upper) is not int:
            raise ValueError("Uniform bounds must be integers.")
        if self.lower > self.upper:
            raise ValueError("Uniform bounds must be ordered.")


@dataclass(frozen=True)
class DiscreteGaussian:
    """Independent centered discrete Gaussian coefficients, specified by stddev."""

    stddev: Decimal

    def __post_init__(self) -> None:
        value = Decimal(str(self.stddev))
        if not value.is_finite() or value <= 0:
            raise ValueError("stddev must be finite and positive.")
        object.__setattr__(self, "stddev", value)


Distribution = Union[SparseTernary, Ternary, Uniform, DiscreteGaussian]


@dataclass(frozen=True)
class Parameters:
    """CKKS security instance with ring degree n and exact attacked modulus q."""

    n: int
    q: int
    secret: Distribution
    error: Distribution

    def __post_init__(self) -> None:
        _integer("n", self.n, 1)
        _integer("q", self.q, 2)
        for name in ("secret", "error"):
            distribution = getattr(self, name)
            if not isinstance(distribution, (SparseTernary, Ternary, Uniform, DiscreteGaussian)):
                raise TypeError(f"Unsupported {name} distribution description.")
            if isinstance(distribution, SparseTernary) and distribution.h > self.n:
                raise ValueError(f"The {name} Hamming weight exceeds n.")
