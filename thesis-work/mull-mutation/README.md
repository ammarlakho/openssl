# Mull mutation testing over OpenSSL

Runs [Mull](https://github.com/mull-project/mull) against OpenSSL test
binaries inside a container, so mutation scores do not depend on the host's
compiler. The image carries only the toolchain (Ubuntu 24.04, clang-18,
mull-18); OpenSSL itself is compiled through a bind mount, so incremental
`make` works and the image rarely needs rebuilding.

Everything goes through `mull.sh`, run from the repo root.

## Commands

| Command | Description |
|---|---|
| `mull.sh build` | Build the toolchain image (once) |
| `mull.sh compile-normal` | Configure + build without coverage (~1600 mutants) |
| `mull.sh compile-cov [test]` | Reconfigure + rebuild **with coverage** (~50 mutants) |
| `mull.sh configure-cov` | Just the coverage reconfigure, shared across many tests |
| `mull.sh build-test <test>` | Build one test binary in an already-configured tree |
| `mull.sh mutate [test]` | Run mutation testing against a built test binary |
| `mull.sh run` | `compile` + `mutate` |
| `mull.sh run-cov [test]` | `compile-cov` + `mutate` |
| `mull.sh test-recipe <name>` | Run one test recipe (name without the `NN-` prefix) |
| `mull.sh shell` | Interactive shell in the container |

A test argument is a path without the `.c` and without any subdirectory, e.g.
`./test/generated_test`. It defaults to `./test/bio_enc_test`.

First run:

```bash
./thesis-work/mull-mutation/mull.sh build
./thesis-work/mull-mutation/mull.sh run-cov ./test/bio_enc_test
```

## Why coverage mode

`compile-cov` is the mode that matters. Without coverage instrumentation Mull
mutates everything linked into the binary — around 1600 mutants, most of them
in libcrypto code the test was never meant to reach. With it, Mull mutates
only what the test actually executes, around 50 for `bio_enc_test`. Scoring
against the uninstrumented set measures the size of OpenSSL, not the quality
of the test.

`compile-cov` does a `make clean` first, because the coverage flags have to
apply to the whole tree.

Running a modified existing test needs no recompile of the tree, only
`build-test`.

## Which mutators

`mull.yml` pins ten operators — arithmetic, relational, logical, constant
assignment, and void-call removal — and excludes `testutil` so the harness
itself is not mutated. Pinning them keeps the mutant set fixed across runs, so
a score is comparable between experiments; Mull's default set varies with
version.

## Reports

`mutate` always asks for two reporters, so the terminal warnings are not the
only record:

```
thesis-work/experiments/results/<name>/<name>.json   Mutation Testing Elements schema
thesis-work/experiments/results/<name>/<name>.txt    the same warnings, as a file
thesis-work/experiments/results/<name>/<name>.html   Elements viewer for that JSON
```

The JSON is the one to parse. It carries an overall `mutationScore` plus, per
file, every mutant as `{id, mutatorName, replacement, location, status}` where
status is `Killed` / `Survived` / `NotCovered` / `Timeout`. `MULL_REPORT_DIR`
and `MULL_REPORT_NAME` override the destination.

These per-run directories are gitignored — tens of MB per batch. The
append-only `results.jsonl` / `results.csv` next to them is what survives in
the tree.

`mutate` passes `--allow-surviving --mutation-score-threshold 0`: a surviving
mutant is the measurement, not a failure, so a non-zero exit means Mull itself
could not run.

## Scoring a batch

For more than one test, drive it from the Python side rather than calling this
script per test — it does the slow coverage reconfigure once for the whole
batch and records every score:

```bash
./thesis-work/scripts/llm_test.py mutate --all
./thesis-work/scripts/llm_test.py mutation-report
```

See `../scripts/README.md`.
