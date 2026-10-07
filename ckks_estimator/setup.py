"""Prepare backend sources and their private runtime."""

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from urllib.request import urlopen

from .installation import BACKENDS, backend_path, install_backend
from ._runtime import runtime_command


_MICROMAMBA = "2.3.3-0"
_DOWNLOADS = {
    ("Darwin", "arm64"): ("osx-arm64", "aa23d0e01d6f492f43aa86720c0f4c8db91978b81f8af46a852f6c4fcf6737d5"),
    ("Darwin", "x86_64"): ("osx-64", "d61b4b752be3464e7162688f568327888cd826c5ec14462e44f42816660e77fd"),
    ("Linux", "x86_64"): ("linux-64", "9496f94a8b78c536573c93d946ec9bba74bd9ff79ee55aaa4b546e30db8f511b"),
    ("Linux", "aarch64"): ("linux-aarch64", "0289350c2c89f7410554041e25b444cce30df326b227e70ead3e4a1e0b316286"),
}


def _managed_runtime(root):
    target = _DOWNLOADS.get((platform.system(), platform.machine()))
    if target is None:
        raise RuntimeError("Managed Sage setup supports macOS and Linux on x86_64 and ARM64. "
                           "Use WSL on Windows, or supply --sage PATH.")
    subdir, digest = target
    executable = root / f"micromamba-{_MICROMAMBA}"
    if not executable.is_file() or sha256(executable.read_bytes()).hexdigest() != digest:
        url = f"https://github.com/mamba-org/micromamba-releases/releases/download/{_MICROMAMBA}/micromamba-{subdir}"
        with urlopen(url, timeout=120) as response:
            binary = response.read()
        if sha256(binary).hexdigest() != digest:
            raise RuntimeError("Runtime installer checksum mismatch.")
        with tempfile.NamedTemporaryFile(dir=root, delete=False) as stream:
            temporary = stream.name
            stream.write(binary)
        temporary = Path(temporary)
        temporary.chmod(0o755)
        temporary.replace(executable)
    manager = [str(executable), "--no-rc", "--root-prefix", str(root / "mamba")]
    prefix = str(root / "sage-10.9")
    subprocess.run([*manager, "create", "--yes", "--prefix", prefix,
                    "--override-channels", "--channel", "conda-forge", "sage=10.9"], check=True)
    return (*manager, "run", "--prefix", prefix, "sage")


def setup(backends=("malb", "tabog"), *, sage=None):
    """Use an existing Sage or install a private one, then install backend sources."""
    backends = tuple(backends)
    if not backends or set(backends) - BACKENDS.keys():
        raise ValueError(f"Choose backends from {tuple(BACKENDS)}.")
    root = backend_path("malb").parent
    root.mkdir(parents=True, exist_ok=True)
    sage = sage or os.environ.get("CKKS_ESTIMATOR_SAGE")
    if sage is not None:
        command = runtime_command(sage)
    else:
        try:
            command = runtime_command()
        except RuntimeError:
            print("Installing the private Sage runtime. This can require several GB.", flush=True)
            command = _managed_runtime(root)
    subprocess.run([*command, "-python", "-c", "import sage.all, scipy, fpylll"], check=True)
    paths = [install_backend(name) for name in backends]
    configuration = root / "runtime.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as stream:
        json.dump({"command": command}, stream)
        temporary = stream.name
    Path(temporary).replace(configuration)
    return paths
