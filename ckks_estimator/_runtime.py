"""Persistent subprocess transport for Sage-dependent backends."""

import atexit
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
from threading import Lock

from .backend import EstimationError, UnsupportedParameters
from .installation import backend_path
from ._serialization import dumps, loads


def runtime_command(sage=None):
    executable = sage or os.environ.get("CKKS_ESTIMATOR_SAGE")
    if executable:
        resolved = shutil.which(str(executable))
        if not resolved:
            raise RuntimeError(f"Sage executable not found: {executable}.")
        return (resolved,)
    configuration = backend_path("malb").parent / "runtime.json"
    if configuration.is_file():
        command = json.loads(configuration.read_text())["command"]
        if not isinstance(command, list) or not command or not all(isinstance(s, str) for s in command):
            raise ValueError("Invalid backend runtime command.")
        return tuple(command)
    executable = shutil.which("sage")
    if executable:
        return (executable,)
    raise RuntimeError("Backend runtime is missing. Run 'ckks-estimator setup' once.")


class Worker:
    def __init__(self, command):
        self.command = command
        self.process = None
        self.log = None
        self.lock = Lock()
        self.owner = os.getpid()
        self.generation = 0
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

    def request(self, operation, **arguments):
        if self.owner != os.getpid():
            raise EstimationError("Create a new estimator in the child process before using it.")
        with self.lock:
            try:
                if self.process is None:
                    self.log = tempfile.TemporaryFile()
                    self.process = subprocess.Popen(
                        [*self.command, "-python", "-u", str(Path(__file__).with_name("_worker.py"))],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                        text=True, encoding="utf-8", start_new_session=True,
                    )
                    self.generation += 1
                self.process.stdin.write(dumps({"operation": operation, **arguments}) + "\n")
                self.process.stdin.flush()
                line = self.process.stdout.readline()
                if not line:
                    self.log.seek(max(0, self.log.seek(0, 2) - 4000))
                    raise EstimationError("Backend worker exited: " + self.log.read().decode(errors="replace"))
                response = loads(line)
            except (OSError, ValueError, EstimationError) as exc:
                self.close()
                raise EstimationError(f"Backend runtime failed: {exc}") from exc
            except BaseException:
                self.close()
                raise
            if "error" in response:
                error = {"UnsupportedParameters": UnsupportedParameters, "ValueError": ValueError,
                         "TypeError": TypeError}.get(response["error"], EstimationError)
                raise error(response["message"])
            return response["result"]


_workers = {}
_lock = Lock()


def _after_fork():
    global _lock
    _lock = Lock()
    _workers.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def worker(sage=None):
    command = runtime_command(sage)
    key = (os.getpid(), command)
    with _lock:
        if key not in _workers:
            _workers[key] = Worker(command)
        return _workers[key]
