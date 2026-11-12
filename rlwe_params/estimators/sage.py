"""Ordinary Python adapters for backends executed in Sage workers."""

from pathlib import Path
from threading import Lock

from ..installation import BACKENDS, backend_path
from .._runtime import pool


class SageEstimator:
    """A registered backend through isolated Sage runtimes.

    attacks=None selects the backend's default attacks. Concurrent calls each
    use their own worker process.
    """

    def __init__(self, backend, path=None, *, attacks=None, cost_model="MATZOV",
                 shape_model="GSA", sage=None):
        path = backend_path(backend) if path is None else Path(path).resolve()
        if not (path / BACKENDS[backend].source).is_file():
            raise ValueError(f"Missing {backend} sources. Run 'rlwe-params setup {backend}' "
                             "or pass a checkout path.")
        self.backend = backend
        self._pool = pool(sage)
        self._options = {
            "path": str(path), "attacks": None if attacks is None else tuple(attacks),
            "cost_model": cost_model, "shape_model": shape_model,
        }
        self._lock = Lock()
        self._loaded = {}
        self._active = set()
        with self._pool.worker() as worker:
            self._load(worker)

    def _load(self, worker):
        metadata = worker.request("load", backend=self.backend, options=self._options)
        self._id = metadata.pop("id")
        self.__dict__.update(metadata)
        self._loaded[worker] = worker.generation

    def _request(self, operation, **arguments):
        with self._pool.worker() as worker:
            with self._lock:
                self._active.add(worker)
            try:
                if worker.process is None or self._loaded.get(worker) != worker.generation:
                    self._load(worker)
                return worker.request(operation, id=self._id, **arguments)
            finally:
                with self._lock:
                    self._active.discard(worker)

    def supports(self, parameters):
        return self._request("supports", parameters=parameters)

    def attack(self, parameters, name):
        return self._request("attack", parameters=parameters, attack=name)

    def cancel(self):
        with self._lock:
            for worker in self._active:
                worker.cancel()


class MalbEstimator(SageEstimator):
    """malb/lattice-estimator through isolated Sage runtimes."""

    def __init__(self, path=None, **options):
        super().__init__("malb", path, **options)


class TabOgEstimator(SageEstimator):
    """TabOg's sparse attacks through isolated Sage runtimes."""

    def __init__(self, path=None, **options):
        super().__init__("tabog", path, **options)
