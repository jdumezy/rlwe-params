from hashlib import sha256
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

setup_module = importlib.import_module("ckks_estimator.setup")


class SetupTests(unittest.TestCase):
    def test_setup_validates_existing_runtime_before_publishing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(setup_module, "backend_path", return_value=root / "malb"):
                with patch.object(setup_module, "runtime_command", return_value=("/example/sage",)):
                    with patch.object(setup_module.subprocess, "run") as run:
                        with patch.object(setup_module, "install_backend", return_value=root / "malb"):
                            self.assertEqual(setup_module.setup(["malb"], sage="/example/sage"), [root / "malb"])
                    self.assertEqual(json.loads((root / "runtime.json").read_text()),
                                     {"command": ["/example/sage"]})
                    self.assertIn("import sage.all, scipy, fpylll", run.call_args.args[0])
                with patch.object(setup_module, "runtime_command", side_effect=RuntimeError("missing")):
                    with patch.object(setup_module, "_managed_runtime") as managed:
                        with self.assertRaisesRegex(RuntimeError, "missing"):
                            setup_module.setup(sage="/missing/sage")
                        managed.assert_not_called()

    def test_managed_bootstrap_checks_digest_and_keeps_environment_private(self):
        binary = b"test runtime manager"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = {(setup_module.platform.system(), setup_module.platform.machine()):
                      ("test-platform", sha256(binary).hexdigest())}
            with patch.object(setup_module, "_DOWNLOADS", target):
                with patch.object(setup_module, "urlopen", return_value=io.BytesIO(binary)):
                    with patch.object(setup_module.subprocess, "run") as run:
                        command = setup_module._managed_runtime(root)
                arguments = run.call_args.args[0]
                self.assertIn("sage=10.9", arguments)
                self.assertEqual(arguments[arguments.index("--prefix") + 1], str(root / "sage-10.9"))
                self.assertEqual(command[-4:], ("run", "--prefix", str(root / "sage-10.9"), "sage"))
                (root / f"micromamba-{setup_module._MICROMAMBA}").unlink()
                with patch.object(setup_module, "urlopen", return_value=io.BytesIO(b"wrong")):
                    with self.assertRaisesRegex(RuntimeError, "checksum"):
                        setup_module._managed_runtime(root)
                self.assertFalse((root / f"micromamba-{setup_module._MICROMAMBA}").exists())


if __name__ == "__main__":
    unittest.main()
