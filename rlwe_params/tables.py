"""Tables of the largest logq meeting a security target, over ring dimensions and secrets."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from decimal import Decimal
import json
from pathlib import Path
import tempfile
from threading import Event, Lock
import time
from typing import Callable, Optional, Sequence, Union

from .api import max_logq
from .backend import EstimationError
from .evaluation import default_jobs
from ._runtime import process_limit
from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary
from .profiles import profile as _profile


FORMAT = 1


def secret(label):
    """"ternary" is uniform on {-1, 0, 1}. An integer h is a sparse ternary Hamming weight."""
    if label == "ternary":
        return Ternary()
    if type(label) is int and label > 0:
        return SparseTernary.weight(label)
    raise ValueError(f"Unknown secret {label!r}. Use 'ternary' or a positive Hamming weight.")


def _key(log_n, label, target):
    return f"{log_n}:{label}:{target}"


def _guess(records, log_n, label, target):
    """Extrapolate from the two smaller ring dimensions, assuming logq grows linearly with n."""
    previous = [records.get(_key(log_n - step, label, target), {}).get("logq") for step in (1, 2)]
    if previous[0] is None or records[_key(log_n - 1, label, target)]["status"] != "boundary":
        return None
    if previous[1] is None:
        return 2 * previous[0]
    return round(previous[0] * previous[0] / previous[1])


class _Stoppable:
    """An estimator that refuses new work once the table run stops."""

    def __init__(self, estimator, stop):
        self._estimator = estimator
        self._stop = stop

    def __getattr__(self, name):
        return getattr(self._estimator, name)

    def _check(self):
        if self._stop.is_set():
            raise EstimationError("The table run was interrupted.")

    def supports(self, parameters):
        self._check()
        return self._estimator.supports(parameters)

    def attack(self, parameters, name):
        self._check()
        return self._estimator.attack(parameters, name)


def _prior(records, log_n, label, target):
    """Rank attacks by their boundary costs in the nearest completed cell with this secret."""
    candidates = [record for record in records.values()
                  if record["secret"] == label and record["costs"]]
    if not candidates:
        return ()
    nearest = min(candidates, key=lambda record: (abs(record["log_n"] - log_n),
                                                  abs(record["target"] - target)))
    costs = nearest["costs"]
    return tuple(sorted(costs, key=lambda attack: Decimal(costs[attack])))


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, suffix=".tmp") as stream:
        stream.write(text)
        temporary = Path(stream.name)
    temporary.replace(path)


def _markdown(settings, records, log_ns, labels, target):
    header = " | ".join(str(label) for label in labels)
    lines = [f"# Ciphertext modulus table for {target} bits of security", "",
             f"| logn \\ h | {header} |", "| -------- |" + " --: |" * len(labels)]
    for log_n in log_ns:
        cells = []
        for label in labels:
            record = records.get(_key(log_n, label, target))
            if record is None:
                cells.append("")
            elif record["status"] == "lower_bound_unsafe":
                cells.append("--")
            elif record["status"] == "upper_bound":
                cells.append(f">={record['logq']}")
            else:
                cells.append(str(record["logq"]))
        lines.append(f"| {log_n} | " + " | ".join(cells) + " |")
    revisions = sorted({(name, revision) for record in records.values()
                        if record["target"] == target for name, revision in record["revisions"].items()})
    profile = settings["profile"]
    lines += [
        "",
        f"Each cell is the largest `logq`, with `q = 2^logq` the largest attacked modulus, "
        f"such that every attack of the estimators below costs at least {target} bits at that "
        f"`logq`, and the next `logq` has an attack below {target} bits. Integer `logq` from {settings['lower']} "
        f"to the upper bound were searched. `--`: the lower bound already fails. "
        f"`>=U`: the upper bound `U` meets the target. Empty: not computed.",
        "",
        f"- Ring dimension `n = 2^logn`. Error: discrete Gaussian, `sigma = {settings['sigma']}`. "
        f"Samples: {'unlimited' if settings['samples'] is None else settings['samples']}.",
        "- Secret: `h` coefficients in {-1, 1}, `h // 2` of them equal to 1, "
        "or `ternary`, uniform on {-1, 0, 1}.",
        f"- Profile `{profile['name']}`: cost model {profile['cost_model']}, "
        f"shape model {profile['shape_model']}, backends {', '.join(profile['backends'])}.",
    ]
    lines += [f"- `{name}` revision `{revision}`." for name, revision in revisions]
    return "\n".join(lines) + "\n"


def run_table(*, log_ns: Sequence[int], secrets: Sequence[Union[int, str]], targets: Sequence[int],
              output: Union[str, Path], sigma="3.2", samples: Optional[int] = None,
              profile="matzov", lower: int = 15, upper: Optional[int] = None, window: int = 2,
              jobs: Optional[int] = None, cache=True, estimators: Optional[Callable] = None,
              progress: Optional[Callable] = None):
    """Search every (logn, secret, target) cell and write results.json and Markdown tables.

    Completed cells are written immediately and reused when their backend
    revisions match. A cell's guess extrapolates the same secret and target at
    smaller ring dimensions, which run first. Up to jobs backend processes run
    across cells. upper defaults to n // 16. estimators, if given, maps a
    reference Parameters to estimators instead of the profile's backends.
    progress receives (cell key, logq, costs, full) for each evaluation, and
    (cell key, record) when a cell completes.
    Return the records and the failures, mapping cell keys to exceptions.
    """
    log_ns = sorted(dict.fromkeys(log_ns))
    labels = sorted({label for label in secrets if label != "ternary"}) + \
        (["ternary"] if "ternary" in secrets else [])
    targets = sorted(dict.fromkeys(targets))
    if not log_ns or not labels or not targets:
        raise ValueError("Select at least one ring dimension, secret, and target.")
    for label in labels:
        secret(label)
    if any(type(value) is not int or value < 1 for value in (*log_ns, *targets)):
        raise ValueError("Ring dimensions and targets must be positive integers.")
    jobs = default_jobs() if jobs is None else jobs
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer.")
    selected = _profile(profile)
    error = DiscreteGaussian(sigma)
    settings = {
        "format": FORMAT, "sigma": str(error.stddev), "samples": samples, "lower": lower,
        "upper": upper, "window": window,
        "profile": {"name": selected.name, "cost_model": selected.cost_model,
                    "shape_model": selected.shape_model, "backends": list(selected.backends),
                    "attacks": {name: list(attacks) for name, attacks in selected.attacks.items()}},
    }
    output = Path(output)
    results = output / "results.json"
    records = {}
    if results.is_file():
        stored = json.loads(results.read_text())
        if stored.get("settings") != settings:
            raise ValueError(f"{results} was written with other settings. Choose another output.")
        records = stored["cells"]
    factory = selected.estimators if estimators is None else estimators
    stop, active, lock = Event(), [], Lock()

    def save():
        _write(results, json.dumps({"settings": settings, "cells": dict(sorted(records.items()))},
                                   indent=2) + "\n")
        for target in targets:
            _write(output / f"{target}bits_security.md",
                   _markdown(settings, records, log_ns, labels, target))

    def run(log_n, label, target, guess, prior, workers):
        key = _key(log_n, label, target)
        n = 1 << log_n
        cell_upper = n // 16 if upper is None else upper
        reference = Parameters(n, 2, secret(label), error, samples)
        cell_estimators = tuple(_Stoppable(estimator, stop) for estimator in factory(reference))
        with lock:
            active.extend(cell_estimators)
        revisions = {estimator.name: estimator.revision for estimator in cell_estimators}
        previous = records.get(key)
        if previous is not None and previous["revisions"] == revisions:
            return previous
        counts = {"points": 0, "full": 0}

        def report(point, costs, full):
            counts["points"] += 1
            counts["full"] += full
            if progress is not None:
                progress(key, point, costs, full)

        started = time.monotonic()
        if guess is not None:
            guess = max(lower, min(cell_upper, guess))
        result = max_logq(n=n, secret=reference.secret, error=error, samples=samples,
                          upper=cell_upper, target=target, lower=lower, guess=guess, window=window,
                          estimators=cell_estimators, cache=cache, jobs=workers, progress=report,
                          prior=prior)
        costs = {} if result.logq is None else result.costs[result.logq]
        return {
            "log_n": log_n, "secret": label, "target": target, "logq": result.logq,
            "status": result.status,
            "security_bits": None if result.logq is None else str(result.security_bits),
            "binding": min(costs, key=costs.get) if costs else None,
            "costs": {attack: str(bits) for attack, bits in costs.items()},
            "checked_interval": list(result.checked_interval), "upper": cell_upper,
            "revisions": revisions, "evaluations": counts["points"],
            "full_evaluations": counts["full"], "seconds": round(time.monotonic() - started, 1),
        }

    cells = [(log_n, label, target) for log_n in log_ns for target in targets for label in labels]
    pending, running, failures = list(cells), {}, {}
    with process_limit(jobs), ThreadPoolExecutor(jobs) as pool:
        try:
            while pending or running:
                # A cell waits for the same secret and target at the previous ring dimension.
                ready = [cell for cell in pending
                         if cell[0] - 1 not in log_ns or _key(cell[0] - 1, *cell[1:]) in records
                         or _key(cell[0] - 1, *cell[1:]) in failures]
                slots = jobs - sum(workers for _, workers in running.values())
                for cell in ready[:max(0, slots)]:
                    workers = max(1, slots // min(slots, len(ready)))
                    guess = _guess(records, *cell)
                    prior = _prior(records, *cell)
                    running[pool.submit(run, *cell, guess, prior, workers)] = (cell, workers)
                    pending.remove(cell)
                if not running:
                    break
                finished, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in finished:
                    cell, _ = running.pop(future)
                    key = _key(*cell)
                    try:
                        records[key] = future.result()
                    except Exception as exc:
                        failures[key] = exc
                        if progress is not None:
                            progress(key, exc)
                        continue
                    save()
                    if progress is not None:
                        progress(key, records[key])
        except BaseException:
            # Interrupted: refuse new attacks and abandon running ones, keeping saved cells.
            stop.set()
            for future in running:
                future.cancel()
            with lock:
                for estimator in active:
                    cancel = getattr(estimator, "cancel", None)
                    if cancel is not None:
                        cancel()
            raise

    for cell in pending:
        failures[_key(*cell)] = RuntimeError("A previous ring dimension failed.")
    save()
    return records, failures
