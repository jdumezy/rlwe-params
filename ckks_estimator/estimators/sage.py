"""Ordinary Python adapters for backends executed in a Sage worker."""

from pathlib import Path

from ..installation import BACKENDS, backend_path
from .._runtime import worker


class SageEstimator:
    """A registered backend through an isolated Sage runtime."""

    def __init__(self, backend, path=None, *, attacks=None, cost_model="MATZOV",
                 shape_model="GSA", sage=None):
        path = backend_path(backend) if path is None else Path(path).resolve()
        if not (path / BACKENDS[backend].source).is_file():
            raise ValueError(f"Missing {backend} sources. Run 'ckks-estimator setup {backend}' "
                             "or pass a checkout path.")
        self.backend = backend
        self._worker = worker(sage)
        self._options = {
            "path": str(path), "attacks": None if attacks is None else tuple(attacks),
            "cost_model": cost_model, "shape_model": shape_model,
        }
        self._load()

    def _load(self):
        metadata = self._worker.request("load", backend=self.backend, options=self._options)
        self._id = metadata.pop("id")
        self.__dict__.update(metadata)
        self._generation = self._worker.generation

    def _request(self, operation, parameters):
        if self._worker.process is None or self._worker.generation != self._generation:
            self._load()
        return self._worker.request(operation, id=self._id, parameters=parameters)

    def supports(self, parameters):
        return self._request("supports", parameters)

    def estimate(self, parameters):
        return self._request("estimate", parameters)


class MalbEstimator(SageEstimator):
    """malb/lattice-estimator through an isolated Sage runtime."""

    def __init__(self, path=None, **options):
        super().__init__("malb", path, **options)


class TabOgEstimator(SageEstimator):
    """TabOg's sparse attacks through an isolated Sage runtime."""

    def __init__(self, path=None, **options):
        super().__init__("tabog", path, **options)
