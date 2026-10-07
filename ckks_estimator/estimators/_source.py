"""Content-based source identification."""

from hashlib import sha256
from pathlib import Path
from typing import Mapping


def source_revision(roots: Mapping[str, Path], runtime: Mapping[str, str]) -> str:
    """Hash Python source trees and runtime versions, excluding checkout paths."""
    digest = sha256()
    for name, root in sorted(roots.items()):
        paths = sorted(root.rglob("*.py")) if root.is_dir() else [root]
        for path in paths:
            relative = path.relative_to(root) if root.is_dir() else Path(root.name)
            data = path.read_bytes()
            digest.update(f"{name}/{relative.as_posix()}\0{len(data)}\0".encode())
            digest.update(data)
    for name, version in sorted(runtime.items()):
        digest.update(f"{name}\0{version}\0".encode())
    return "sha256:" + digest.hexdigest()
