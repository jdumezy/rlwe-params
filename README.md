<p align="center">
  <img src="docs/logo.svg" alt="rlwe-params" width="440">
</p>

Parameter selection for RLWE-based homomorphic encryption, such as CKKS, from existing lattice estimators.

`rlwe-params` is not an estimator itself.
It runs lattice estimators as backends and takes the minimum over all of their attacks.
It finds the largest modulus for which every one of these attacks meets a security target, for a given ring dimension, secret distribution, and error.
It works for sparse, ternary, uniform, and Gaussian secrets.

## Installation

`rlwe-params` is plain Python 3.11+, and runs each estimator as a separate process.
The bundled estimators are written for [SageMath](https://www.sagemath.org/), so they need Sage with SciPy and fpylll, and Git.

From a clone of this repository:

```bash
git clone https://github.com/jdumezy/rlwe-params.git
cd rlwe-params
python3 -m pip install -e .
rlwe-params setup
```

Or install without cloning, with `python3 -m pip install git+https://github.com/jdumezy/rlwe-params.git`.

`setup` checks Sage and installs the pinned estimator sources.
It uses `sage` on `PATH`, or `--sage PATH`, a `sage` launcher or a Python that imports Sage.

Without a local Sage, use Docker.

```bash
docker build -t rlwe-params .
docker run --rm -v "$PWD:/work" rlwe-params estimate --log-n 16 --log-q 1475 --h 192
```

## Precomputed tables

[`tables/128bits_security.md`](tables/128bits_security.md) gives the largest `logq` for 128 bits of security, with `logn` from 12 to 17, sparse secrets with `h` from 32 to 2048, and ternary secrets.

Each cell is the largest `logq` such that every attack of the listed estimators costs at least the target at `q = 2^logq`, and the next `logq` has an attack below it.
`--` means even the smallest searched `logq` fails, and `>=U` means the upper search bound passes.
Each table lists its conventions and estimator revisions, and `results.json` records the binding attack and the cost of every attack at each cell's `logq`.

## Usage

Check a parameter set, with each attack's cost.

```bash
rlwe-params estimate --log-n 16 --log-q 1475 --h 192 --details
```

Find the largest `logq` that meets a target.

```bash
rlwe-params search --log-n 16 --h 192 --target 128 --progress
```

Generate tables.
Cells run in parallel, start from the results of smaller ring dimensions, and are saved as they complete.
An interrupted run resumes where it stopped.

```bash
rlwe-params table --log-n 12 13 14 15 16 17 --h 32 64 128 192 256 512 1024 2048 --ternary \
  --target 128 192 256 --jobs 32 --output tables/ --progress
```

The same is available from Python.

```python
from rlwe_params import DiscreteGaussian, SparseTernary, estimate, max_logq

secret, error = SparseTernary.weight(192), DiscreteGaussian("3.2")
print(estimate(n=2**16, q=2**1475, secret=secret, error=error).security_bits)
print(max_logq(n=2**16, secret=secret, error=error, upper=4096, target=128).logq)
```

Conventions:

- `q` is the largest modulus an attacker sees, such as `QP` when key-switching keys are public.
- A sparse secret of weight `h` has `h // 2` coefficients equal to 1 and the rest equal to -1.
- The error is a discrete Gaussian with `sigma = 3.2` by default, and the number of samples is unlimited by default.
- Costs are rounded down. Results only hold against the attacks of the selected estimators, under their cost models. They are not security proofs, and a new attack can lower them.

## Estimators

Every estimate uses the MATZOV reduction cost model [[MATZOV22]](https://doi.org/10.5281/zenodo.6412487) and the GSA shape model.

| Backend | Attacks | Applies to |
| ------- | ------- | ---------- |
| [malb/lattice-estimator](https://github.com/malb/lattice-estimator) [[APS15]](https://doi.org/10.1515/jmc-2015-0016) | uSVP, BDD, BDD hybrid, BDD MitM hybrid, dual, MATZOV dual hybrid, dual MitM hybrid. Arora-GB and BKW on request. | All secrets |
| [TabOg/mlwe-hybrids](https://github.com/TabOg/mlwe-hybrids) [[Ogi26]](https://eprint.iacr.org/2026/279) | Rotated primal hybrid, four variants | Sparse secrets, power-of-two rings |

To cite results, see [Citation](#citation).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to add an estimator or an attack.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you use `rlwe-params` or its tables, please cite it together with the estimators and cost model it ran, since the results come from them.

```bibtex
@misc{dumezy2026rlweparams,
  author       = {Jules Dumezy},
  title        = {rlwe-params: {RLWE} Parameter Selection from Lattice Estimators},
  howpublished = {\url{https://github.com/jdumezy/rlwe-params}},
  year         = {2026}
}

@article{APS15,
  author  = {Martin R. Albrecht and Rachel Player and Sam Scott},
  title   = {On the concrete hardness of {Learning with Errors}},
  journal = {Journal of Mathematical Cryptology},
  volume  = {9},
  number  = {3},
  pages   = {169--203},
  year    = {2015},
  doi     = {10.1515/jmc-2015-0016}
}

@misc{Ogi26,
  author       = {Tabitha Ogilvie},
  title        = {On the Concrete Hardness Gap Between {MLWE} and {LWE}},
  howpublished = {Cryptology ePrint Archive, Paper 2026/279},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/279}
}

@misc{MATZOV22,
  author = {{MATZOV}},
  title  = {Report on the Security of {LWE}: Improved Dual Lattice Attack},
  year   = {2022},
  doi    = {10.5281/zenodo.6412487}
}
```
