"""Estimators that run as separate processes speaking the backend protocol."""

from pathlib import Path
from threading import Lock

from ..installation import BACKENDS, backend_path
from ..protocol import encode_parameters
from ..results import AttackEstimate
from .._runtime import backend_command, pool


class ProcessEstimator:
    """A registered backend, run as its own process in any language.

    attacks=None selects the backend's default attacks. Concurrent calls each
    use their own process.
    """

    def __init__(self, backend, path=None, *, attacks=None, cost_model="MATZOV",
                 shape_model="GSA", sage=None):
        entry = BACKENDS[backend]
        options = {"attacks": None if attacks is None else list(attacks),
                   "cost_model": cost_model, "shape_model": shape_model}
        if entry.url is not None:
            path = backend_path(backend) if path is None else Path(path).resolve()
            if not (path / entry.source).is_file():
                raise ValueError(f"Missing {backend} sources. Run 'rlwe-params setup {backend}' "
                                 "or pass a checkout path.")
            options["path"] = str(path)
        self.backend = backend
        self._options = options
        self._pool = pool(backend_command(backend, sage))
        self._lock = Lock()
        self._active = set()
        description = self._request("describe")
        self.name = description["name"]
        self.revision = description["revision"]
        self.cost_model = description["cost_model"]
        self.configuration = description["configuration"]
        self.attacks = tuple(description["attacks"])

    def _request(self, operation, **arguments):
        with self._pool.worker() as worker:
            with self._lock:
                self._active.add(worker)
            try:
                return worker.request({"op": operation, "options": self._options, **arguments})
            finally:
                with self._lock:
                    self._active.discard(worker)

    def supports(self, parameters):
        return self._request("supports", parameters=encode_parameters(parameters))

    def attack(self, parameters, name):
        bits = self._request("attack", parameters=encode_parameters(parameters), attack=name)
        return AttackEstimate(name, bits)

    def cancel(self):
        with self._lock:
            for worker in self._active:
                worker.cancel()


class MalbEstimator(ProcessEstimator):
    """malb/lattice-estimator, run in Sage."""

    def __init__(self, path=None, **options):
        super().__init__("malb", path, **options)


class TabOgEstimator(ProcessEstimator):
    """TabOg's sparse attacks, run in Sage."""

    def __init__(self, path=None, **options):
        super().__init__("tabog", path, **options)
