"""Command-line parameter estimation, modulus search, tables, and backend setup."""

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from .api import estimate, max_logq
from .installation import BACKENDS
from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform
from .profiles import PROFILES, profile


def _integer(value):
    return int(value, 16 if value.lower().startswith("0x") else 10)


def _positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer.")
    return value


def _common(query):
    query.add_argument("--sigma", default="3.2", help="Error standard deviation. Default: 3.2.")
    query.add_argument("--samples", type=_positive, help="Available samples. Default: unlimited.")
    query.add_argument("--profile", choices=tuple(PROFILES), default="matzov",
                       help="Cost model, shape model, and attacks. Default: matzov.")
    query.add_argument("--backend", choices=tuple(BACKENDS), action="append",
                       help="Restrict the profile's backends. Default: all applicable backends.")
    query.add_argument("--jobs", type=_positive, help="Parallel Sage workers. Default: at most 4.")
    caching = query.add_mutually_exclusive_group()
    caching.add_argument("--no-cache", action="store_true")
    caching.add_argument("--cache", type=Path, help="Use this cache database.")


def _parameters(query):
    dimension = query.add_mutually_exclusive_group(required=True)
    dimension.add_argument("--n", type=_positive)
    dimension.add_argument("--log-n", type=_positive, help="Ring dimension is 2**LOG_N.")
    secret = query.add_mutually_exclusive_group(required=True)
    secret.add_argument("--h", type=_positive, help="Sparse ternary secret with Hamming weight H.")
    secret.add_argument("--ternary", action="store_true", help="Secret uniform on {-1, 0, 1}.")
    secret.add_argument("--uniform", nargs=2, type=int, metavar=("LOWER", "UPPER"))
    secret.add_argument("--gaussian", metavar="STDDEV")
    _common(query)
    output = query.add_mutually_exclusive_group()
    output.add_argument("--details", action="store_true", help="Include each attack's estimate.")
    output.add_argument("--json", action="store_true", help="Include attack results and provenance as JSON.")


def _search_bounds(query, upper_help):
    query.add_argument("--lower", type=_positive, default=15, help="Smallest allowed logq. Default: 15.")
    query.add_argument("--upper", type=_positive, help=upper_help)
    query.add_argument("--window", type=int, default=2,
                       help="Points checked below the boundary with the binding attack. Default: 2.")
    query.add_argument("--progress", action="store_true", help="Report each evaluation on stderr.")


def _describe(point, costs, full):
    attack = min(costs, key=costs.get)
    return (f"logq={point}: {float(costs[attack]):.2f} bits ({attack}), "
            f"{'all attacks' if full else 'binding attack'}")


def _progress(point, costs, full):
    print(_describe(point, costs, full), file=sys.stderr, flush=True)


def _table_progress(key, *event):
    if len(event) == 3:
        message = _describe(*event)
    elif isinstance(event[0], Exception):
        message = f"failed: {event[0]}"
    else:
        record = event[0]
        message = (f"done: logq={record['logq']} ({record['status']}), "
                   f"{record['evaluations']} evaluations, {record['seconds']} s")
    print(f"[{key}] {message}", file=sys.stderr, flush=True)


def _print_search(result, arguments):
    if arguments.json:
        print(json.dumps({
            "logq": result.logq, "security_bits": None if result.logq is None else str(result.security_bits),
            "target": str(result.target), "status": result.status,
            "checked_interval": result.checked_interval, "certified": result.certified,
            "costs": {str(point): {attack: str(bits) for attack, bits in costs.items()}
                      for point, costs in result.costs.items()},
        }, indent=2))
        return
    if result.logq is None:
        print("The lower search bound does not meet the security target.")
    else:
        print(f"logq={result.logq} (q=2**{result.logq}): {result.security_bits} bits")
        if result.status == "upper_bound":
            print("The upper search bound is safe.")
    if arguments.details:
        for point, costs in result.costs.items():
            scope = "all attacks" if point in result.certified else "partial"
            for attack, bits in costs.items():
                print(f"logq={point} ({scope}) / {attack}: {bits} bits")


def _print_estimate(result, arguments):
    if arguments.json:
        print(json.dumps({
            "security_bits": str(result.security_bits), "unsupported": result.unsupported,
            "complete": result.complete,
            "estimates": [{"estimator": e.estimator, "revision": e.revision,
                           "cost_model": e.cost_model, "configuration": e.configuration,
                           "attacks": {a.attack: str(a.security_bits) for a in e.attacks}}
                          for e in result.estimates],
        }, indent=2))
        return
    print(f"{result.security_bits} bits")
    if arguments.details:
        for e in result.estimates:
            for a in e.attacks:
                print(f"{e.estimator} / {a.attack}: {a.security_bits} bits")
    for name in result.unsupported:
        print(f"{name}: unsupported parameters")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ckks-estimator")
    commands = parser.add_subparsers(dest="command", required=True)
    setup_parser = commands.add_parser("setup", help="Install backend sources for a Sage runtime.")
    setup_parser.add_argument("backends", nargs="*", metavar="BACKEND", default=list(BACKENDS))
    setup_parser.add_argument("--sage", help="Use this Sage executable. Default: sage on PATH.")

    query = commands.add_parser("estimate", help="Estimate security for CKKS parameters.")
    _parameters(query)
    modulus = query.add_mutually_exclusive_group(required=True)
    modulus.add_argument("--q", type=_integer, help="Exact modulus, decimal or hexadecimal.")
    modulus.add_argument("--log-q", type=_positive, help="Modulus is exactly 2**LOG_Q.")

    search = commands.add_parser(
        "search", help="Find the largest certified logq for a security target.",
        description="Locate the boundary with the binding attack, then certify it with all attacks. "
                    "Assumes a mostly decreasing curve with small, rare irregularities.")
    _parameters(search)
    _search_bounds(search, "Largest allowed logq. Default: n // 16.")
    search.add_argument("--target", default="128", help="Required security in bits. Default: 128.")
    search.add_argument("--guess", type=_positive, help="Initial logq guess within the bounds.")

    table = commands.add_parser(
        "table", help="Search a grid of ring dimensions, secrets, and targets.",
        description="Write results.json and one Markdown table per target to OUTPUT. "
                    "Completed cells are reused when rerun with the same settings.")
    table.add_argument("--log-n", type=_positive, nargs="+", required=True)
    table.add_argument("--h", type=_positive, nargs="*", default=[], help="Sparse Hamming weights.")
    table.add_argument("--ternary", action="store_true", help="Add a uniform ternary secret column.")
    table.add_argument("--target", type=_positive, nargs="+", default=[128],
                       help="Security targets in bits. Default: 128.")
    table.add_argument("--output", type=Path, required=True, help="Output directory.")
    _common(table)
    _search_bounds(table, "Largest allowed logq. Default: n // 16 for each row.")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "setup":
            from .setup import setup

            for path in setup(arguments.backends, sage=arguments.sage):
                print(path)
            return
        selected = profile(arguments.profile)
        if arguments.backend:
            selected = selected.restrict(arguments.backend)
        cache = False if arguments.no_cache else arguments.cache or True
        if arguments.command == "table":
            from .tables import run_table

            secrets = [*arguments.h, *(["ternary"] if arguments.ternary else [])]
            _, failures = run_table(
                log_ns=arguments.log_n, secrets=secrets, targets=arguments.target,
                output=arguments.output, sigma=arguments.sigma, samples=arguments.samples,
                profile=selected, lower=arguments.lower, upper=arguments.upper,
                window=arguments.window, jobs=arguments.jobs, cache=cache,
                progress=_table_progress if arguments.progress else None)
            for key, exc in failures.items():
                print(f"[{key}] failed: {exc}", file=sys.stderr)
            print(arguments.output)
            if failures:
                parser.exit(1)
            return
        if arguments.h is not None:
            secret = SparseTernary.weight(arguments.h)
        elif arguments.ternary:
            secret = Ternary()
        elif arguments.uniform is not None:
            secret = Uniform(*arguments.uniform)
        else:
            secret = DiscreteGaussian(arguments.gaussian)
        n = arguments.n if arguments.n is not None else 1 << arguments.log_n
        error = DiscreteGaussian(arguments.sigma)
        if arguments.command == "search":
            result = max_logq(n=n, secret=secret, error=error, samples=arguments.samples,
                              upper=n // 16 if arguments.upper is None else arguments.upper,
                              lower=arguments.lower, target=arguments.target,
                              guess=arguments.guess, window=arguments.window, profile=selected,
                              cache=cache, jobs=arguments.jobs,
                              progress=_progress if arguments.progress else None)
            _print_search(result, arguments)
            return
        parameters = Parameters(n, arguments.q if arguments.q is not None else 1 << arguments.log_q,
                                secret, error, arguments.samples)
        _print_estimate(estimate(parameters, profile=selected, cache=cache, jobs=arguments.jobs),
                        arguments)
    except (ValueError, TypeError, ArithmeticError, RuntimeError, OSError,
            sqlite3.Error, subprocess.SubprocessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
