# Ciphertext modulus table for 128 bits of security

Sparse ternary secrets with Hamming weight `h`, and dense secrets:

| logn \ h | 32 | 64 | 128 | 192 | 256 | 512 | 1024 | 2048 | ternary |
| -------- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| 12 | 19 | 57 | 85 | 96 | 100 | 104 | 105 | 106 | 106 |
| 13 | 37 | 112 | 167 | 186 | 196 | 208 | 211 | 213 | 214 |
| 14 | 77 | 227 | 332 | 367 | 387 | 415 | 424 | 428 | 430 |
| 15 | 162 | 464 | 665 | 737 | 771 | 826 | 851 | 861 | 868 |
| 16 | 342 | 954 | 1345 | 1475 | 1545 | 1651 | 1707 | 1730 | 1746 |
| 17 | 744 | 1963 | 2721 | 2982 | 3101 | 3315 | 3423 | 3480 | 3522 |

Each cell is the largest `logq`, with `q = 2^logq` the largest attacked modulus, such that every attack of the estimators below costs at least 128 bits at that `logq`, and the next `logq` has an attack below 128 bits. Integer `logq` from 15 to the upper bound were searched. `--`: the lower bound already fails. `>=U`: the upper bound `U` meets the target. Empty: not computed.

- Ring dimension `n = 2^logn`. Error: discrete Gaussian, `sigma = 3.2`. Samples: unlimited.
- Sparse ternary: `h` coefficients in {-1, 1}, `h // 2` of them equal to 1, the rest 0.
- `ternary`: uniform on {-1, 0, 1}.
- Profile `matzov`: cost model MATZOV, shape model GSA, backends malb, tabog.
- `TabOg/mlwe-hybrids` revision `tabog=sha256:441e93713654ab307628a5913654059efd2e22f74fb4e18c9962c6374f68de30|malb=sha256:5931f4aefcc97da2580618512cb8b2f2569f34499506c3e3e3ded09cdd215cee`.
- `malb/lattice-estimator` revision `sha256:780c700c4839a95a4243d676f164400fd2523bef76895b961cede79d5230fb56`.
