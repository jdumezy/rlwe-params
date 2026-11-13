"""Persistent backend processes speaking the JSON-lines protocol."""

import atexit
from contextlib import contextmanager
from functools import lru_cache
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
from threading import Lock

from .backend import EstimationError
from .installation import BACKENDS, backends_root
from .protocol import canonical, raise_error


# Python adapters import rlwe_params from this checkout or installation.
_PACKAGE_ROOT = str(Path(__file__).resolve().parent.parent)


@lru_cache(maxsize=None)
def _interpreter(executable):
    resolved = shutil.which(str(executable))
    if not resolved:
        raise RuntimeError(f"Sage executable not found: {executable}.")
    # Both the sage launcher and Sage's Python accept -c, unlike sage -python.
    process = subprocess.run([resolved, "-c", "import sys, sage.all; print(sys.executable)"],
                             capture_output=True, text=True)
    lines = process.stdout.strip().splitlines()
    if process.returncode or not lines or not Path(lines[-1]).is_file():
        raise RuntimeError(f"{resolved} cannot import Sage: {process.stderr.strip()}")
    return lines[-1]


def sage_python(sage=None):
    """The Python interpreter of Sage, for backends that need it.

    sage, or $RLWE_PARAMS_SAGE, is a sage launcher or a Python that imports
    Sage. Otherwise use the interpreter recorded by setup, or sage on PATH.
    """
    executable = sage or os.environ.get("RLWE_PARAMS_SAGE")
    if executable:
        return _interpreter(executable)
    configuration = backends_root() / "runtime.json"
    if configuration.is_file():
        python = json.loads(configuration.read_text()).get("python")
        if not isinstance(python, str) or not python:
            raise RuntimeError(f"Invalid {configuration}. Rerun rlwe-params setup.")
        return python
    if shutil.which("sage"):
        return _interpreter("sage")
    raise RuntimeError("SageMath was not found. Install it, pass --sage PATH, "
                       "or use the Docker image.")


def backend_command(name, sage=None):
    """The command that runs a registered backend, with "{sage}" expanded."""
    return tuple(sage_python(sage) if argument == "{sage}" else argument
                 for argument in BACKENDS[name].command)


class Worker:
    def __init__(self, command):
        self.command = command
        self.process = None
        self.log = None
        self.lock = Lock()
        self.owner = os.getpid()
        atexit.register(self.close)

    def close(self):
        if self.owner != os.getpid():
            return
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            self.process.stdin.close()
            self.process.stdout.close()
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def cancel(self):
        """Kill a running request from another thread. That request then fails."""
        process = self.process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def request(self, message):
        """Send one request and return its result, raising the error a backend reports."""
        if self.owner != os.getpid():
            raise EstimationError("Create a new estimator in the child process before using it.")
        with self.lock:
            try:
                if self.process is None:
                    self.log = tempfile.TemporaryFile()
                    environment = dict(os.environ, PYTHONUNBUFFERED="1")
                    environment["PYTHONPATH"] = os.pathsep.join(
                        filter(None, [_PACKAGE_ROOT, environment.get("PYTHONPATH")]))
                    self.process = subprocess.Popen(
                        self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=self.log, text=True, encoding="utf-8", env=environment,
                        start_new_session=True,
                    )
                self.process.stdin.write(canonical(message) + "\n")
                self.process.stdin.flush()
                line = self.process.stdout.readline()
                if not line:
                    self.log.seek(max(0, self.log.seek(0, 2) - 4000))
                    raise EstimationError("Backend worker exited: " + self.log.read().decode(errors="replace"))
                response = json.loads(line)
                if not isinstance(response, dict) or ("result" in response) == ("error" in response):
                    raise ValueError(f"Malformed backend response: {line.strip()[:200]}")
            except (OSError, ValueError, EstimationError) as exc:
                self.close()
                raise EstimationError(f"Backend runtime failed: {exc}") from exc
            except BaseException:
                self.close()
                raise
            if "error" in response:
                raise_error(response["error"])
            return response["result"]


class Pool:
    """Workers for one backend command, started on demand and reused."""

    def __init__(self, command):
        self.command = command
        self.idle = []
        self.size = 0

    @contextmanager
    def worker(self):
        evicted = None
        with _lock:
            if self.idle:
                selected = self.idle.pop()
            else:
                if _limit is not None and sum(pool.size for pool in _pools.values()) >= _limit:
                    # Make room by closing the longest idle worker of any backend.
                    owner = next((pool for pool in _pools.values() if pool.idle), None)
                    if owner is not None:
                        evicted = owner.idle.pop(0)
                        owner.size -= 1
                selected = Worker(self.command)
                self.size += 1
        if evicted is not None:
            evicted.close()
        try:
            yield selected
        finally:
            with _lock:
                self.idle.append(selected)


_pools = {}
_lock = Lock()
_limit = None


@contextmanager
def process_limit(count):
    """Keep at most count backend processes inside this block, closing idle ones first."""
    global _limit
    previous, _limit = _limit, count
    try:
        yield
    finally:
        _limit = previous


def _after_fork():
    global _lock
    _lock = Lock()
    _pools.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def pool(command):
    command = tuple(command)
    with _lock:
        if command not in _pools:
            _pools[command] = Pool(command)
        return _pools[command]
