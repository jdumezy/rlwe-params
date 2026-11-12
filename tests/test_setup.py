import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

setup_module = importlib.import_module("rlwe_params.setup")


class SetupTests(unittest.TestCase):
    def test_setup_validates_the_runtime_before_publishing_configuration(self):
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
                (root / "runtime.json").unlink()
                with patch.object(setup_module, "runtime_command", side_effect=RuntimeError("missing")):
                    with patch.object(setup_module, "install_backend") as install:
                        with self.assertRaisesRegex(RuntimeError, "missing"):
                            setup_module.setup()
                        install.assert_not_called()
                self.assertFalse((root / "runtime.json").exists())
        with self.assertRaisesRegex(ValueError, "Choose backends"):
            setup_module.setup(["unknown"])


if __name__ == "__main__":
    unittest.main()
