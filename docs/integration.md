# Using the tables in a library

Libraries can derive their parameter presets from the tables, or check their presets against them.
This page describes the JSON tables, how to look up a parameter set, and how to keep a library up to date.

## Where to get the tables

Each table comes as JSON next to its Markdown version, such as [`tables/128bits_security.json`](../tables/128bits_security.json).
Each release also attaches the JSON tables as assets:

- One release: `https://github.com/jdumezy/rlwe-params/releases/download/<tag>/128bits_security.json`
- The latest release: `https://github.com/jdumezy/rlwe-params/releases/latest/download/128bits_security.json`

Read the tables from a release, not from `main`, which can change at any time.

## Format

The top level gives:

- `format`: the version of this format.
- `target`: the security target in bits.
- `error`: the error distribution, a discrete Gaussian with `sigma`.
- `samples`: the number of samples, `null` for unlimited.
- `lower`: the smallest searched `logq`.
- `profile`: the cost model, shape model, and estimator backends.
- `cells`: one entry per ring dimension and secret.

Each entry of `cells` has:

- `log_n`: the ring dimension is `n = 2^log_n`.
- `secret`, with its `kind`:
  - `ternary` or `binary`: uniform on the integers from `min` to `max`.
  - `gaussian`: a discrete Gaussian with `sigma`.
  - `sparse_ternary` or `sparse_binary`: exactly `h` nonzero coefficients, `ones` of them equal to 1 and `minus_ones` equal to -1.
- `status` and `max_log_q`:
  - `boundary`: `max_log_q` is the largest `logq` meeting the target.
  - `at_least_upper`: `max_log_q` is the upper search bound, `upper`, which meets the target. The largest `logq` may be higher.
  - `below_lower`: even `lower` fails, and `max_log_q` is `null`.
  - `error`: an estimator failed on this cell, `max_log_q` is `null`, and `error` gives its message.
- `security_bits`: the cost of the cheapest attack at `max_log_q`, as a decimal string.
- `binding_attack`: the cheapest attack at `max_log_q`.
- `revisions`: the revision of each estimator that produced the cell.

`q` is the largest modulus an attacker sees, such as `QP` when key-switching keys are public.
New fields may be added without changing `format`, so ignore the fields you do not use.
`format` is incremented when a field is removed or its meaning changes.

## Looking up a parameter set

A parameter set with ring dimension `2^log_n`, a secret, and largest modulus `Q` meets the target when the cell of its `log_n` and secret has status `boundary` or `at_least_upper`, and `Q <= 2^max_log_q`.
The error and number of samples must also match the table's.
In particular, check `sigma`: a library using another one needs its own tables, generated with `rlwe-params table --sigma`.

```python
import json

with open("128bits_security.json") as stream:
    table = json.load(stream)
if table["format"] != 1:
    raise RuntimeError("Unsupported rlwe-params table format.")


def max_log_q(table, log_n, kind, h=None):
    """The largest log2 of Q meeting the target, or None without a result."""
    for cell in table["cells"]:
        if cell["log_n"] == log_n and cell["secret"]["kind"] == kind and cell["secret"].get("h") == h:
            if cell["status"] in ("boundary", "at_least_upper"):
                return cell["max_log_q"]
            return None
    return None


# Q is the preset's largest modulus, such as QP.
limit = max_log_q(table, 16, "sparse_ternary", h=192)
assert table["error"]["sigma"] == "3.2"
assert limit is not None and Q <= 2**limit
```

A library can run this check in its tests for every preset, or generate its presets from the table at build time.

## Keeping a library up to date

Do not fetch the latest tables while building or running.
A build would then not be reproducible, a preset could silently exceed its limit after the tables are regenerated, and anyone able to change the download would control the parameters.

Instead, keep a copy of the tables in the library, and update it automatically by pull request.
A scheduled job downloads the latest release and opens a pull request when the tables changed.
The library's tests then check every preset against the new tables before anyone merges it.

For a library on GitHub, the following workflow does this every week.
It keeps the tables in `third_party/rlwe-params`.

```yaml
name: Update rlwe-params tables

on:
  schedule:
    - cron: "0 5 * * 1"
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  update:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: ${{ github.token }}
    steps:
      - uses: actions/checkout@v5
      - name: Download the latest tables
        run: |
          tag=$(gh release view --repo jdumezy/rlwe-params --json tagName -q .tagName)
          gh release download "$tag" --repo jdumezy/rlwe-params --pattern '*bits_security.json' \
            --dir third_party/rlwe-params --clobber
          echo "$tag" > third_party/rlwe-params/VERSION
      - name: Open a pull request if they changed
        run: |
          git add third_party/rlwe-params
          git diff --cached --quiet && exit 0
          tag=$(cat third_party/rlwe-params/VERSION)
          git switch -c "rlwe-params-$tag"
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git commit -m "Update rlwe-params tables to $tag"
          git push --force origin "rlwe-params-$tag"
          gh pr create --fill || true
```

Two repository settings matter:

- The workflow can open pull requests only if Settings → Actions → General allows GitHub Actions to create pull requests.
- Pull requests opened with the default token do not start other workflows. To run the library's tests on them, use a personal access token or a GitHub App token instead of `github.token`.

If the library must download the tables during its build, pin a release and its checksum, so that a build always gets the same file.
For example, with CMake:

```cmake
set(RLWE_PARAMS_TAG v0.2.0)
file(DOWNLOAD
  https://github.com/jdumezy/rlwe-params/releases/download/${RLWE_PARAMS_TAG}/128bits_security.json
  ${CMAKE_BINARY_DIR}/rlwe-params/128bits_security.json
  EXPECTED_HASH SHA256=<checksum>
  TLS_VERIFY ON)
```

The checksum of each asset is its `digest`, shown on the release page and by `gh release view <tag> --repo jdumezy/rlwe-params --json assets`.
