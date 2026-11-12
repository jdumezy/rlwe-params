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

## Adding an attack to an existing backend

1. In [`rlwe_params/estimators/_malb.py`](rlwe_params/estimators/_malb.py), add its name to `ATTACKS` and its call to `_algorithms()`.
   For TabOg, add its options to `ATTACKS` in [`_tabog.py`](rlwe_params/estimators/_tabog.py).
2. Add it to `DEFAULT_ATTACKS` unless it is much slower than the others and never close to binding, as for Arora-GB and BKW.
3. Add a backend test comparing its cost with a direct call to the upstream function.

The adapter file is part of the backend revision, so cached results are invalidated automatically.

## Adding an estimator backend

1. Write an adapter in `rlwe_params/estimators/_<name>.py`. It runs inside Sage and provides:
   - `name`, `cost_model`, and `revision`, a content hash of the upstream sources and the adapter from `source_revision()`;
   - `attacks`, the selected attack names, and `configuration`, every other setting that affects a cost;
   - `supports(parameters)`, without running estimation;
   - `attack(parameters, name)`, returning an `AttackEstimate` with the log2 cost rounded down.
     Infinity is a valid cost. Raise `UnsupportedParameters` or `EstimationError` otherwise.

   The constructor takes `path=None, *, attacks=None, cost_model="MATZOV", shape_model="GSA"`.
   `cost_model` must use the same names as the profiles, such as `MATZOV`, so results stay comparable.
2. Register it in `BACKENDS` in [`rlwe_params/installation.py`](rlwe_params/installation.py) with its repository, a pinned commit, a source file that identifies a checkout, the adapter as `module:Class`, and optionally `applies`, a plain-Python test of the parameters it handles.
3. Add a backend test comparing its costs with direct upstream calls, as in [`tests/test_tabog.py`](tests/test_tabog.py).

Profiles use every registered backend by default, so tables and searches include it without further changes.
An estimator that does not need Sage can implement the same interface in plain Python and be passed with `estimators=`.
