"""Install pinned backend sources. Requires Git, but not Sage."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


BACKENDS = {
    "malb": (
        "https://github.com/malb/lattice-estimator.git",
        "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
        (),
    ),
    "tabog": (
        "https://github.com/TabOg/mlwe-hybrids.git",
        "a92f335665eef69927d2d8f49832bd595a6dac32",
        ("PrimalHybrid/lattice_estimator",),
    ),
}


def backend_path(name: str, directory=None) -> Path:
    """Locate pinned sources without installing or modifying them."""
    if name not in BACKENDS:
        raise ValueError(f"Unknown backend {name!r}. Choose from {tuple(BACKENDS)}.")
    if directory is None:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        directory = os.environ.get("CKKS_ESTIMATOR_BACKENDS", root / "ckks-estimator" / "backends")
    return Path(directory).expanduser().resolve() / f"{name}-{BACKENDS[name][1]}"


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
    url, revision, submodules = BACKENDS[name]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backends", nargs="+", choices=tuple(BACKENDS))
    parser.add_argument("--directory", type=Path, help="Backend installation directory.")
    arguments = parser.parse_args()
    try:
        for name in arguments.backends:
            print(install_backend(name, directory=arguments.directory))
    except (OSError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
