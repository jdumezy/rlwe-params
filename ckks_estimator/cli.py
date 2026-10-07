"""Command-line parameter estimation and backend setup."""

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess

from .api import estimate
from .parameters import DiscreteGaussian, Parameters, SparseTernary, Ternary, Uniform


def _integer(value):
    return int(value, 16 if value.lower().startswith("0x") else 10)


def _positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer.")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ckks-estimator")
    commands = parser.add_subparsers(dest="command", required=True)
    setup_parser = commands.add_parser("setup", help="Prepare backend sources and runtime.")
    setup_parser.add_argument("backends", nargs="*", metavar="BACKEND", default=["malb", "tabog"])
    setup_parser.add_argument("--sage", help="Use this Sage executable instead of a managed runtime.")

    query = commands.add_parser("estimate", help="Estimate security for CKKS parameters.")
    dimension = query.add_mutually_exclusive_group(required=True)
    dimension.add_argument("--n", type=_positive)
    dimension.add_argument("--log-n", type=_positive, help="Ring dimension is 2**LOG_N.")
    modulus = query.add_mutually_exclusive_group(required=True)
    modulus.add_argument("--q", type=_integer, help="Exact modulus, decimal or hexadecimal.")
    modulus.add_argument("--log-q", type=_positive, help="Modulus is exactly 2**LOG_Q.")
    secret = query.add_mutually_exclusive_group(required=True)
    secret.add_argument("--sparse", nargs=2, type=int, metavar=("POSITIVE", "NEGATIVE"))
    secret.add_argument("--ternary", action="store_true")
    secret.add_argument("--uniform", nargs=2, type=int, metavar=("LOWER", "UPPER"))
    secret.add_argument("--gaussian", metavar="STDDEV")
    query.add_argument("--sigma", required=True, help="Error standard deviation.")
    query.add_argument("--samples", type=_positive, help="Available samples. Default: unlimited.")
    query.add_argument("--backend", choices=("malb", "tabog"), action="append",
                       help="Restrict backends. Default: all applicable backends.")
    caching = query.add_mutually_exclusive_group()
    caching.add_argument("--no-cache", action="store_true")
    caching.add_argument("--cache", type=Path, help="Use this cache database.")
    output = query.add_mutually_exclusive_group()
    output.add_argument("--details", action="store_true", help="Include each attack's estimate.")
    output.add_argument("--json", action="store_true", help="Include attack results and provenance as JSON.")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "setup":
            from .setup import setup

            for path in setup(arguments.backends, sage=arguments.sage):
                print(path)
            return
        if arguments.sparse is not None:
            secret = SparseTernary(*arguments.sparse)
        elif arguments.ternary:
            secret = Ternary()
        elif arguments.uniform is not None:
            secret = Uniform(*arguments.uniform)
        else:
            secret = DiscreteGaussian(arguments.gaussian)
        parameters = Parameters(
            arguments.n if arguments.n is not None else 1 << arguments.log_n,
            arguments.q if arguments.q is not None else 1 << arguments.log_q,
            secret, DiscreteGaussian(arguments.sigma), arguments.samples,
        )
        estimators = None
        if arguments.backend:
            from .estimators import MalbEstimator, TabOgEstimator

            adapters = {"malb": MalbEstimator, "tabog": TabOgEstimator}
            estimators = [adapters[name]() for name in dict.fromkeys(arguments.backend)]
        result = estimate(parameters, estimators=estimators,
                          cache=False if arguments.no_cache else arguments.cache or True)
        if arguments.json:
            print(json.dumps({
                "security_bits": str(result.security_bits), "unsupported": result.unsupported,
                "estimates": [{"estimator": e.estimator, "revision": e.revision,
                               "cost_model": e.cost_model, "configuration": e.configuration,
                               "attacks": {a.attack: str(a.security_bits) for a in e.attacks}}
                              for e in result.estimates],
            }, indent=2))
        else:
            print(f"{result.security_bits} bits")
            if arguments.details:
                for e in result.estimates:
                    for a in e.attacks:
                        print(f"{e.estimator} / {a.attack}: {a.security_bits} bits")
            for name in result.unsupported:
                print(f"{name}: unsupported parameters")
    except (ValueError, TypeError, ArithmeticError, RuntimeError, OSError,
            sqlite3.Error, subprocess.SubprocessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
