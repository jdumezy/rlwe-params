"""Install backend sources and record the Sage runtime that evaluates them."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from .installation import BACKENDS, backend_path, install_backend
from ._runtime import runtime_command


def setup(backends=tuple(BACKENDS), *, sage=None):
    """Check a Sage runtime, install pinned backend sources, and record the runtime.

    Use sage, $RLWE_PARAMS_SAGE, a recorded runtime, or sage on PATH.
    Without SageMath, use the Docker image.
    """
    backends = tuple(backends)
    if not backends or set(backends) - BACKENDS.keys():
        raise ValueError(f"Choose backends from {tuple(BACKENDS)}.")
    root = backend_path("malb").parent
    root.mkdir(parents=True, exist_ok=True)
    command = runtime_command(sage or os.environ.get("RLWE_PARAMS_SAGE"))
    subprocess.run([*command, "-python", "-c", "import sage.all, scipy, fpylll"], check=True)
    paths = [install_backend(name) for name in backends]
    configuration = root / "runtime.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as stream:
        json.dump({"command": list(command)}, stream)
        temporary = stream.name
    Path(temporary).replace(configuration)
    return paths
