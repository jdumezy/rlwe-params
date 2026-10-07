from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ckks_estimator.estimators import MalbEstimator, TabOgEstimator
from ckks_estimator.installation import backend_path, install_backend


def git(path, *arguments):
    return subprocess.run(["git", "-C", str(path), *arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True).stdout.strip()


class InstallationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.destination = self.root / "installed"
        environment = patch.dict("os.environ", {
            "CKKS_ESTIMATOR_BACKENDS": str(self.destination),
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def repository(self, name, filename):
        path = self.root / name
        path.mkdir()
        git(path, "init", "--quiet")
        git(path, "config", "user.name", "Installer test")
        git(path, "config", "user.email", "installer@example.invalid")
        file = path / filename
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("# Source.\n")
        git(path, "add", ".")
        git(path, "commit", "--quiet", "-m", "Initial source")
        return path, git(path, "rev-parse", "HEAD")

    def test_pinned_install_reuse_and_local_change_protection(self):
        source, revision = self.repository("malb", "estimator/__init__.py")
        (source / "later.py").write_text("# Later revision.\n")
        git(source, "add", ".")
        git(source, "commit", "--quiet", "-m", "Later source")
        with patch("ckks_estimator.installation.BACKENDS", {"malb": (str(source), revision, ())}):
            installed = install_backend("malb")
            self.assertEqual(installed, backend_path("malb"))
            self.assertEqual(git(installed, "rev-parse", "HEAD"), revision)
            self.assertFalse((installed / "later.py").exists())
            source.rename(source.with_name("offline"))
            self.assertEqual(install_backend("malb"), installed)
            changed = installed / "estimator" / "__init__.py"
            changed.write_text("# Local edit.\n")
            with self.assertRaisesRegex(RuntimeError, "local changes"):
                install_backend("malb")
            self.assertEqual(changed.read_text(), "# Local edit.\n")

    def test_selected_submodule_uses_its_recorded_revision(self):
        dependency, dependency_revision = self.repository("malb", "estimator/__init__.py")
        source, _ = self.repository("tabog", "PrimalHybrid/lwe_rot_primal.py")
        submodule = "PrimalHybrid/lattice_estimator"
        git(source, "submodule", "add", str(dependency), submodule)
        with (source / ".gitmodules").open("a") as file:
            file.write('[submodule "unused"]\n\tpath = unused\n\turl = /missing/unused\n')
        git(source, "add", ".")
        git(source, "commit", "--quiet", "-m", "Pin dependency")
        revision = git(source, "rev-parse", "HEAD")
        (dependency / "later.py").write_text("# New dependency.\n")
        git(dependency, "add", ".")
        git(dependency, "commit", "--quiet", "-m", "Advance dependency")
        with patch("ckks_estimator.installation.BACKENDS",
                   {"tabog": (str(source), revision, (submodule,))}):
            installed = install_backend("tabog")
            self.assertEqual(git(installed / submodule, "rev-parse", "HEAD"), dependency_revision)
            self.assertFalse((installed / "unused").exists())
            self.assertEqual(install_backend("tabog"), installed)
            git(installed, "submodule", "deinit", "--force", "--", submodule)
            with self.assertRaisesRegex(RuntimeError, "dependency"):
                install_backend("tabog")

    def test_failed_download_is_not_published_and_adapters_do_not_install(self):
        source, _ = self.repository("malb", "estimator/__init__.py")
        with patch("ckks_estimator.installation.BACKENDS", {"malb": (str(source), "0" * 40, ())}):
            with self.assertRaisesRegex(RuntimeError, "Git failed"):
                install_backend("malb")
            self.assertEqual(list(self.destination.iterdir()), [])
        for adapter in (MalbEstimator, TabOgEstimator):
            with self.assertRaisesRegex(ValueError, "ckks-estimator-install"):
                adapter()
        self.assertEqual(list(self.destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
