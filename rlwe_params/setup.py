"""Install backend sources and record the Sage runtime that evaluates them."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from .installation import BACKENDS, backends_root, install_backend
from ._runtime import sage_python


def setup(backends=tuple(BACKENDS), *, sage=None):
    """Check the Sage runtime, install pinned backend sources, and record Sage's Python.

    sage, or $RLWE_PARAMS_SAGE, is a sage launcher or a Python that imports
    Sage. Default: sage on PATH.
    Without SageMath, use the Docker image.
    """
    backends = tuple(backends)
    if not backends or set(backends) - BACKENDS.keys():
        raise ValueError(f"Choose backends from {tuple(BACKENDS)}.")
    root = backends_root()
    root.mkdir(parents=True, exist_ok=True)
    python = sage_python(sage or os.environ.get("RLWE_PARAMS_SAGE") or "sage")
    subprocess.run([python, "-c", "import sage.all, scipy, fpylll"], check=True)
    paths = [install_backend(name) for name in backends if BACKENDS[name].url]
    configuration = root / "runtime.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as stream:
        json.dump({"python": python}, stream)
        temporary = stream.name
    Path(temporary).replace(configuration)
    return paths
