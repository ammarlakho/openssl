
# Mull Mutation Testing — OpenSSL

## Quick Reference

| Command | Description |
|---|---|
| `./mull-mutation/mull.sh build` | Build **toolchain** image (Ubuntu + Mull + clang; rarely needed) |
| `./mull-mutation/mull.sh compile` | Configure + build `bio_enc_test` — **no coverage** (~1600 mutants) |
| `./mull-mutation/mull.sh compile-cov` | Reconfigure + rebuild **with coverage** (`make clean` first; ~50 mutants) |
| `./mull-mutation/mull.sh mutate` | Run mutation testing against `bio_enc_test` |
| `./mull-mutation/mull.sh shell` | Open an interactive shell in the container |
| `./mull-mutation/mull.sh run` | `compile` + `mutate` |
| `./mull-mutation/mull.sh run-cov` | `compile-cov` + `mutate` |
| `./mull-mutation/mull.sh configure-cov` | Just the coverage reconfigure, shared across many tests |
| `./mull-mutation/mull.sh build-test <test>` | Build one test binary in an already-configured tree |

First time: `./mull-mutation/mull.sh build` → `./mull-mutation/mull.sh compile-cov` → `./mull-mutation/mull.sh mutate`

---

Use compile-cov since you want to avoid creating mutants in code that `bio_enc_test` never reaches.



### Running tests:
`./thesis-work/mull-mutation/mull.sh compile-normal`
`./thesis-work/mull-mutation/mull.sh test-recipe test_bio_enc_generated` (recipe name without the number- prefix)

Note: If existing test is modified, no need to recompile for just running the test
Q: Do we reallly need to do make clean in compile-normal?

### Running mutation testing:
`./thesis-work/mull-mutation/mull.sh run-cov ./test/generated_test`  (test file name without .c and without any nested directories inside test)
`./thesis-work/mull-mutation/mull.sh compile-cov ./test/generated_test`  (test file name without .c and without any nested directories inside test)
`./thesis-work/mull-mutation/mull.sh mutate ./test/generated_test` (test file name without .c and without any nested directories inside test)



### Structured reports

`mutate` always asks Mull for two reporters, so the terminal wall of
`file:line:col` warnings is no longer the only record:

```
thesis-work/experiments/results/<name>/<name>.json   Mutation Testing Elements schema
thesis-work/experiments/results/<name>/<name>.txt    the same warnings, as a file
thesis-work/experiments/results/<name>/<name>.html   Elements HTML viewer for that JSON
```

The JSON is the one to parse. It carries an overall `mutationScore` plus, for
each file, every mutant as `{id, mutatorName, replacement, location, status}`
where status is `Killed` / `Survived` / `NotCovered` / `Timeout`. Override the
destination with `MULL_REPORT_DIR` and `MULL_REPORT_NAME`.

`mutate` also passes `--allow-surviving --mutation-score-threshold 0`: a
surviving mutant is the measurement, not a failure, so a non-zero exit now
means Mull itself could not run.

To score a batch of generated tests and collect the numbers, use the driver
rather than this script directly:

```bash
./thesis-work/scripts/llm_test.py mutate --all
./thesis-work/scripts/llm_test.py mutation-report --csv
```

which also keeps an append-only `thesis-work/experiments/results/results.csv` across
experiments.

See `../scripts/README.md`.
