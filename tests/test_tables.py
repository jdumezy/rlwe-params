from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
from threading import Lock
import unittest
from unittest.mock import patch

from ckks_estimator import AttackEstimate, SparseTernary, Ternary, run_table
from ckks_estimator.cli import main
from ckks_estimator.tables import secret


class Curve:
    """Security proportional to n / logq, lower for sparser secrets."""

    name = "curve"
    cost_model = "MATZOV"
    configuration = {}
    attacks = ("primal", "dual")

    def __init__(self, reference, revision="r1", log=None, fail=None):
        self.reference = reference
        self.revision = revision
        self.log = [] if log is None else log
        self.fail = fail

    def supports(self, parameters):
        return True

    def attack(self, parameters, name):
        logq = parameters.q.bit_length() - 1
        self.log.append((parameters.n, logq, name))
        if self.fail is not None and self.fail(parameters):
            raise RuntimeError("attack failed")
        density = Decimal("3.5") if isinstance(parameters.secret, Ternary) else \
            min(Decimal("3.5"), Decimal(parameters.secret.h) / 20)
        return AttackEstimate(name, density * parameters.n / logq + (0 if name == "primal" else 5))


def expected(log_n, label, target):
    density = Decimal("3.5") if label == "ternary" else min(Decimal("3.5"), Decimal(label) / 20)
    return int(density * (1 << log_n) / target)


class TableTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "tables"
        self.log, self.lock = [], Lock()

    def run_grid(self, revision="r1", fail=None, **options):
        events = []

        def progress(key, *event):
            with self.lock:
                events.append((key, *event))

        settings = {"log_ns": [12, 13, 14], "secrets": ["ternary", 32], "targets": [128, 192],
                    "output": self.output, "cache": False, "jobs": 3,
                    "estimators": lambda reference: [Curve(reference, revision, self.log, fail)],
                    "progress": progress, **options}
        records, failures = run_table(**settings)
        return records, failures, events

    def test_grid_results_tables_and_warm_starts(self):
        records, failures, events = self.run_grid()
        self.assertEqual(failures, {})
        self.assertEqual(len(records), 12)
        for record in records.values():
            self.assertEqual(record["status"], "boundary")
            self.assertEqual(record["logq"], expected(record["log_n"], record["secret"], record["target"]))
            self.assertEqual(record["binding"], "curve / primal")
            self.assertEqual(set(record["costs"]), {"curve / primal", "curve / dual"})
            self.assertEqual(record["revisions"], {"curve": "r1"})
        first = {}
        for key, *event in events:
            if len(event) == 3:
                first.setdefault(key, event[0])
        # Each larger ring dimension starts from the extrapolated smaller ones.
        self.assertEqual(first["13:ternary:128"], 2 * records["12:ternary:128"]["logq"])
        self.assertEqual(first["14:32:192"], round(records["13:32:192"]["logq"] ** 2 /
                                                   records["12:32:192"]["logq"]))
        self.assertLessEqual(records["14:ternary:128"]["evaluations"], 5)
        stored = json.loads((self.output / "results.json").read_text())
        self.assertEqual(stored["cells"], records)
        self.assertEqual(stored["settings"]["profile"]["cost_model"], "MATZOV")
        table = (self.output / "128bits_security.md").read_text()
        self.assertIn("| logn \\ h | 32 | ternary |", table)
        self.assertIn(f"| 13 | {expected(13, 32, 128)} | {expected(13, 'ternary', 128)} |", table)
        self.assertIn("`curve` revision `r1`", table)
        self.assertIn("sigma = 3.2", table)
        self.assertTrue((self.output / "192bits_security.md").is_file())

    def test_rerun_reuses_cells_until_revisions_or_settings_change(self):
        records, _, _ = self.run_grid()
        calls = len(self.log)
        self.assertEqual(self.run_grid()[0], records)
        self.assertEqual(len(self.log), calls)
        changed, _, _ = self.run_grid(revision="r2")
        self.assertGreater(len(self.log), calls)
        self.assertEqual({record["revisions"]["curve"] for record in changed.values()}, {"r2"})
        with self.assertRaisesRegex(ValueError, "other settings"):
            self.run_grid(sigma="3.19")

    def test_failures_are_reported_and_retried(self):
        fail = lambda parameters: parameters.n == 8192 and isinstance(parameters.secret, Ternary)
        records, failures, events = self.run_grid(fail=fail)
        self.assertEqual(set(failures), {"13:ternary:128", "13:ternary:192"})
        self.assertNotIn("13:ternary:128", records)
        self.assertIn("14:ternary:128", records)
        self.assertIn(f"| 13 | {expected(13, 32, 128)} |  |",
                      (self.output / "128bits_security.md").read_text())
        retried, failures, _ = self.run_grid()
        self.assertEqual((len(retried), failures), (12, {}))

    def test_search_limits_and_secret_labels(self):
        records, _, _ = self.run_grid(log_ns=[12], secrets=[1], targets=[128], upper=200)
        self.assertEqual(records["12:1:128"]["status"], "lower_bound_unsafe")
        self.output = self.output.with_name("bounded")
        records, _, _ = self.run_grid(log_ns=[12], secrets=[1, "ternary"], targets=[128], upper=50)
        self.assertEqual((records["12:ternary:128"]["logq"], records["12:ternary:128"]["status"]),
                         (50, "upper_bound"))
        table = (self.output / "128bits_security.md").read_text()
        self.assertIn("| 12 | -- | >=50 |", table)
        self.assertEqual(secret(64), SparseTernary(32, 32))
        self.assertEqual(SparseTernary.weight(7), SparseTernary(3, 4))
        for label in (0, "dense", 1.5):
            with self.assertRaises(ValueError):
                secret(label)
        with self.assertRaisesRegex(ValueError, "at least one"):
            run_table(log_ns=[12], secrets=[], targets=[128], output=self.output)

    def test_cli_builds_the_grid(self):
        arguments = ["table", "--log-n", "12", "13", "--h", "32", "64", "--ternary",
                     "--target", "128", "192", "--output", str(self.output), "--no-cache",
                     "--jobs", "2", "--backend", "malb"]
        output = io.StringIO()
        with patch("ckks_estimator.tables.run_table", return_value=({}, {})) as call, \
                redirect_stdout(output):
            main(arguments)
        options = call.call_args.kwargs
        self.assertEqual((options["log_ns"], options["secrets"], options["targets"]),
                         ([12, 13], [32, 64, "ternary"], [128, 192]))
        self.assertEqual((options["sigma"], options["jobs"], options["cache"]), ("3.2", 2, False))
        self.assertEqual(options["profile"].backends, ("malb",))
        with patch("ckks_estimator.tables.run_table", return_value=({}, {"12:32:128": RuntimeError("x")})):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors, \
                    self.assertRaises(SystemExit) as failure:
                main(arguments)
        self.assertEqual(failure.exception.code, 1)
        self.assertIn("[12:32:128] failed: x", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
