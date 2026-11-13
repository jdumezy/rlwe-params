import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from rlwe_params import _runtime

setup_module = importlib.import_module("rlwe_params.setup")


class SetupTests(unittest.TestCase):
    def test_setup_validates_the_runtime_before_publishing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(setup_module, "backends_root", return_value=root):
                with patch.object(setup_module, "sage_python", return_value="/example/python"):
                    with patch.object(setup_module.subprocess, "run") as run:
                        with patch.object(setup_module, "install_backend", return_value=root / "malb"):
                            self.assertEqual(setup_module.setup(["malb"], sage="/example/sage"), [root / "malb"])
                    self.assertEqual(json.loads((root / "runtime.json").read_text()),
                                     {"python": "/example/python"})
                    self.assertIn("import sage.all, scipy, fpylll", run.call_args.args[0])
                (root / "runtime.json").unlink()
                with patch.object(setup_module, "sage_python", side_effect=RuntimeError("missing")):
                    with patch.object(setup_module, "install_backend") as install:
                        with self.assertRaisesRegex(RuntimeError, "missing"):
                            setup_module.setup()
                        install.assert_not_called()
                self.assertFalse((root / "runtime.json").exists())
        with self.assertRaisesRegex(ValueError, "Choose backends"):
            setup_module.setup(["unknown"])

    def test_sage_python_is_found_through_a_launcher_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "sage"
            # Like sage -c and Sage's Python -c, print the interpreter.
            launcher.write_text(f"#!/bin/sh\n[ \"$1\" = -c ] && echo {sys.executable}\n")
            launcher.chmod(0o755)
            failing = root / "broken"
            failing.write_text("#!/bin/sh\necho 'No module named sage' >&2\nexit 1\n")
            failing.chmod(0o755)
            _runtime._interpreter.cache_clear()
            self.addCleanup(_runtime._interpreter.cache_clear)
            with patch.dict(os.environ, {"RLWE_PARAMS_BACKENDS": str(root)}):
                os.environ.pop("RLWE_PARAMS_SAGE", None)
                self.assertEqual(_runtime.sage_python(str(launcher)), sys.executable)
                self.assertEqual(_runtime.backend_command("malb", str(launcher)),
                                 (sys.executable, "-m", "rlwe_params.adapters.malb"))
                with self.assertRaisesRegex(RuntimeError, "cannot import Sage"):
                    _runtime.sage_python(str(failing))
                (root / "runtime.json").write_text(json.dumps({"python": "/recorded/python"}))
                self.assertEqual(_runtime.sage_python(), "/recorded/python")
                (root / "runtime.json").write_text(json.dumps({"command": ["/old/sage"]}))
                with self.assertRaisesRegex(RuntimeError, "Rerun rlwe-params setup"):
                    _runtime.sage_python()


if __name__ == "__main__":
    unittest.main()
