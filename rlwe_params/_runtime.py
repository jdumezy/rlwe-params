"""Persistent backend processes speaking the JSON-lines protocol."""

import atexit
from contextlib import contextmanager
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


def sage_command(sage=None):
    """The command that starts Sage, for backends that need it."""
    executable = sage or os.environ.get("RLWE_PARAMS_SAGE")
    if executable:
        resolved = shutil.which(str(executable))
        if not resolved:
            raise RuntimeError(f"Sage executable not found: {executable}.")
        return (resolved,)
    configuration = backends_root() / "runtime.json"
    if configuration.is_file():
        command = json.loads(configuration.read_text())["command"]
        if not isinstance(command, list) or not command or not all(isinstance(s, str) for s in command):
            raise ValueError("Invalid backend runtime command.")
        return tuple(command)
    executable = shutil.which("sage")
    if executable:
        return (executable,)
    raise RuntimeError("SageMath was not found. Install it, pass --sage PATH, "
                       "or use the Docker image.")


def backend_command(name, sage=None):
    """The command that runs a registered backend, with "{sage}" expanded."""
    command = []
    for argument in BACKENDS[name].command:
        command.extend(sage_command(sage) if argument == "{sage}" else [argument])
    return tuple(command)


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
        self.lock = Lock()

    @contextmanager
    def worker(self):
        with self.lock:
            selected = self.idle.pop() if self.idle else Worker(self.command)
        try:
            yield selected
        finally:
            with self.lock:
                self.idle.append(selected)


_pools = {}
_lock = Lock()


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
