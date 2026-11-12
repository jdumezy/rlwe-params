"""Named estimation assumptions, shared by every backend."""

from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple

from .installation import BACKENDS
from .parameters import Parameters


@dataclass(frozen=True)
class Profile:
    """Cost model, lattice shape model, and attack selection for all backends.

    attacks maps a backend to its selected attacks. Other backends use their
    defaults. backends restricts the registered backends that may apply.
    """

    name: str
    cost_model: str = "MATZOV"
    shape_model: str = "GSA"
    attacks: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    backends: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        selected = tuple(BACKENDS) if self.backends is None else tuple(self.backends)
        if not selected or len(set(selected)) != len(selected) or set(selected) - BACKENDS.keys():
            raise ValueError(f"Select distinct backends from {tuple(BACKENDS)}.")
        if set(self.attacks) - set(selected):
            raise ValueError("Attack selections must name selected backends.")
        object.__setattr__(self, "backends", selected)
        object.__setattr__(self, "attacks", {name: tuple(attacks) for name, attacks in self.attacks.items()})

    def restrict(self, backends) -> "Profile":
        backends = tuple(dict.fromkeys(backends))
        return Profile(self.name, self.cost_model, self.shape_model,
                       {name: attacks for name, attacks in self.attacks.items() if name in backends},
                       backends)

    def estimators(self, parameters: Parameters):
        """Construct the selected backends that apply to these parameters."""
        from .estimators import ProcessEstimator

        return [ProcessEstimator(name, attacks=self.attacks.get(name), cost_model=self.cost_model,
                              shape_model=self.shape_model)
                for name in self.backends
                if BACKENDS[name].applies is None or BACKENDS[name].applies(parameters)]


PROFILES = {
    "matzov": Profile("matzov"),
}


def profile(value) -> Profile:
    if isinstance(value, Profile):
        return value
    if value not in PROFILES:
        raise ValueError(f"Unknown profile {value!r}. Choose from {tuple(PROFILES)}.")
    return PROFILES[value]
