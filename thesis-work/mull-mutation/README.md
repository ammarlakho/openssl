
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

First time: `./mull-mutation/mull.sh build` → `./mull-mutation/mull.sh compile-cov` → `./mull-mutation/mull.sh mutate`

---

Use compile-cov since you want to avoid creating mutants in code that `bio_enc_test` never reaches.



### Running tests:
`./thesis-work/mull-mutation/mull.sh compile-normal`
`./thesis-work/mull-mutation/mull.sh test-recipe test_bio_enc_generated` (recipe name without the number- prefix)

Note: If existing test is modified, no need to recompile for just running the test
Q: Do we reallly need to do make clean in compile-normal?

### Running mutation testing:
`./thesis-work/mull-mutation/mull.sh compile-cov ./test/generated_test` (test file)
`./thesis-work/mull-mutation/mull.sh mutate ./test/generated_test` (test file)

