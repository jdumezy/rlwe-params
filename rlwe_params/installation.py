"""Backend registry and pinned source installation. Requires Git, but not Sage."""

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Callable, NamedTuple, Optional, Tuple

from .parameters import Parameters, SparseTernary


class Backend(NamedTuple):
    """Pinned sources and the adapter that evaluates them in the Sage worker.

    source is a file whose presence identifies a checkout. adapter is a
    "module:class" reference imported only inside the worker. applies selects
    the backend by default, without Sage. None selects it for all parameters.
    """

    url: str
    revision: str
    submodules: Tuple[str, ...] = ()
    source: str = ""
    adapter: str = ""
    applies: Optional[Callable[[Parameters], bool]] = None


def _sparse_power_of_two(parameters):
    return (isinstance(parameters.secret, SparseTernary) and parameters.secret.h > 0
            and parameters.n >= 2 and parameters.n & (parameters.n - 1) == 0)


# Adding a backend takes an entry here and its adapter module.
BACKENDS = {
    "malb": Backend(
        "https://github.com/malb/lattice-estimator.git",
        "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
        source="estimator/__init__.py",
        adapter="rlwe_params.estimators._malb:MalbEstimator",
    ),
    "tabog": Backend(
        "https://github.com/TabOg/mlwe-hybrids.git",
        "a92f335665eef69927d2d8f49832bd595a6dac32",
        ("PrimalHybrid/lattice_estimator",),
        source="PrimalHybrid/lwe_rot_primal.py",
        adapter="rlwe_params.estimators._tabog:TabOgEstimator",
        applies=_sparse_power_of_two,
    ),
}


def backend_path(name: str, directory=None) -> Path:
    """Locate pinned sources without installing or modifying them."""
    if name not in BACKENDS:
        raise ValueError(f"Unknown backend {name!r}. Choose from {tuple(BACKENDS)}.")
    if directory is None:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        directory = os.environ.get("RLWE_PARAMS_BACKENDS", root / "rlwe-params" / "backends")
    return Path(directory).expanduser().resolve() / f"{name}-{BACKENDS[name].revision}"


def _git(path, *arguments):
    try:
        return subprocess.run(["git", "-C", str(path), *arguments], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Git failed: {exc.stderr.strip()}") from exc


def _verify(path, revision, submodules):
    if _git(path, "rev-parse", "HEAD") != revision:
        raise RuntimeError(f"Unexpected backend revision at {path}.")
    if _git(path, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none"):
        raise RuntimeError(f"Backend has local changes at {path}.")
    for submodule in submodules:
        expected = _git(path, "rev-parse", f"HEAD:{submodule}")
        if not (path / submodule / ".git").exists() or _git(path / submodule, "rev-parse", "HEAD") != expected:
            raise RuntimeError(f"Missing or incorrect backend dependency at {path / submodule}.")


def install_backend(name: str, *, directory=None) -> Path:
    """Install a pinned checkout, or reuse a matching clean installation."""
    destination = backend_path(name, directory)
    url, revision, submodules = BACKENDS[name][:3]
    if destination.exists():
        _verify(destination, revision, submodules)
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=destination.parent) as staging:
        checkout = Path(staging) / "checkout"
        checkout.mkdir()
        _git(checkout, "init", "--quiet")
        _git(checkout, "remote", "add", "origin", url)
        _git(checkout, "fetch", "--depth=1", "origin", revision)
        _git(checkout, "checkout", "--quiet", "--detach", "FETCH_HEAD")
        if submodules:
            _git(checkout, "submodule", "update", "--init", "--depth=1", "--", *submodules)
        _verify(checkout, revision, submodules)
        checkout.rename(destination)
    return destination

