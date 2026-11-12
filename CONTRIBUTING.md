# Contributing

Contributions are welcome, especially new estimators and attacks.
Keep changes small and focused, match the surrounding code, and add tests.

## Running the tests

The plain tests need only Python.

```bash
python3 -m unittest discover -s tests
```

The backend tests also need Sage and the installed estimator sources.

```bash
B=~/.local/share/rlwe-params/backends
RLWE_PARAMS_TEST_SAGE=1 \
MALB_ESTIMATOR_PATH=$B/malb-6019056011d10d7e9c30a0d5da2d2f729fbc2eec \
TABOG_ESTIMATOR_PATH=$B/tabog-a92f335665eef69927d2d8f49832bd595a6dac32 \
sage -python -m unittest discover -s tests
```

## How backends work

The core of `rlwe-params` is plain Python.
Each estimator backend runs as its own process, in any language, and answers requests over a small JSON-lines protocol on stdin and stdout.
This keeps heavy runtimes such as Sage out of the core, and lets the core run attacks in parallel and stop them.

The protocol is specified in [`rlwe_params/protocol.py`](rlwe_params/protocol.py).
A backend answers three requests, each carrying the `options` it was configured with.

```text
{"op": "describe", "options": {...}}
  -> {"result": {"name": ..., "revision": ..., "cost_model": ..., "configuration": {...}, "attacks": [...]}}
{"op": "supports", "options": {...}, "parameters": {...}}
  -> {"result": true}
{"op": "attack", "options": {...}, "parameters": {...}, "attack": "usvp"}
  -> {"result": "128.91"}
```

Errors are `{"error": {"kind": "unsupported" | "invalid" | "failed", "message": ...}}`.
Costs are log2 values as decimal strings, rounded down, or `"Infinity"`.
Parameters look like this.

```json
{"n": 4096, "q": "1267650600228229401496703205376", "samples": null,
 "secret": {"type": "sparse_ternary", "positive": 32, "negative": 32},
 "error": {"type": "discrete_gaussian", "stddev": "3.2"}}
```

Other distribution types are `ternary` and `uniform`, with `lower` and `upper`.
[`tests/toy_backend.py`](tests/toy_backend.py) is a complete backend in a few lines that does not use `rlwe-params`.

## Adding an attack to an existing backend

1. In [`rlwe_params/adapters/malb.py`](rlwe_params/adapters/malb.py), add its name to `ATTACKS` and its call to `_algorithms()`.
   For TabOg, add its options to `ATTACKS` in [`tabog.py`](rlwe_params/adapters/tabog.py).
2. Add it to `DEFAULT_ATTACKS` unless it is much slower than the others and never close to binding, as for Arora-GB and BKW.
3. Add a backend test comparing its cost with a direct call to the upstream function.

The adapter file is part of the backend revision, so cached results are invalidated automatically.

## Adding an estimator backend

1. Write a program that speaks the protocol.
   - `revision` must change whenever the estimator or its configuration changes, for example a hash of its sources, since cached costs are keyed by it.
   - `cost_model` must use the same names as the profiles, such as `MATZOV`, so results stay comparable.
   - `options` contains `attacks` (a list, or `null` for the defaults), `cost_model`, `shape_model`, and `path` for backends with pinned sources.

   For a Python estimator, write a class and call `serve()` from `rlwe_params.protocol`, as the adapters in [`rlwe_params/adapters/`](rlwe_params/adapters/) do.
2. Register it in `BACKENDS` in [`rlwe_params/installation.py`](rlwe_params/installation.py).
   `command` starts it, where `"{sage}"` expands to the Sage command.
   Optionally pin sources that `rlwe-params setup` installs, with `url`, `revision`, and `source`, a file that identifies a checkout.
   `applies` is an optional plain-Python test of the parameters it handles.
3. Add tests: for a Python adapter, compare its costs with direct upstream calls, as in [`tests/test_tabog.py`](tests/test_tabog.py).

Profiles use every registered backend by default, so tables and searches include it without further changes.
