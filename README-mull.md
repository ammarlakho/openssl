# Mull Mutation Testing — OpenSSL

## Quick Reference

| Command | Description |
|---|---|
| `./mull.sh build` | Build **toolchain** image (Ubuntu + Mull + clang; rarely needed) |
| `./mull.sh compile` | Configure + build `bio_enc_test` — **no coverage** (~1600 mutants) |
| `./mull.sh compile-cov` | Reconfigure + rebuild **with coverage** (`make clean` first; ~34 mutants) |
| `./mull.sh mutate` | Run mutation testing against `bio_enc_test` |
| `./mull.sh shell` | Open an interactive shell in the container |
| `./mull.sh run` | `compile` + `mutate` |
| `./mull.sh run-cov` | `compile-cov` + `mutate` |

First time: `./mull.sh build` → `./mull.sh compile` → `./mull.sh mutate`

---

## Why this layout

**Dockerfile** only installs the compiler + Mull. OpenSSL is **not** baked into the image.

- Edits to the Dockerfile that only touch packages still need `build`, but the context is tiny thanks to `.dockerignore` (no uploading the whole OpenSSL tree).
- OpenSSL is built with `./mull.sh compile` over a **bind mount**, so after the first full build, `make` usually only rebuilds what changed.
- **`mull.yml`**: read at `mutate` time — change mutators and re-run `./mull.sh mutate` without `build` or `compile`, unless Mull's docs say your change needs re-instrumentation.

---

## macOS note

Bind-mounting a large tree into Linux can be slow on Docker Desktop. If compiles feel sluggish, a Linux VM/remote builder or the older "compile everything in `docker build`" style can be faster at the cost of less incremental caching.

---

## Without vs with coverage instrumentation

| | `compile` | `compile-cov` |
|---|---|---|
| Extra flags | — | `-fprofile-instr-generate -fcoverage-mapping` |
| Needs `make clean` | No (incremental) | Yes (flag change) |
| Mutants evaluated | ~1600 | ~34 |
| Mull run time | ~150s | ~12s |
| What changes | — | Mull extracts a coverage profile on warm-up and skips mutants in code that `bio_enc_test` never reaches |

The `mull.yml` `excludePaths` filter (ignoring `testutil`) applies to both modes — it's read by `mull-runner` at runtime and also by `mull-ir-frontend` at compile time when coverage is enabled, so coverage mode produces a smaller binary too.

---

## Changing mutators

Edit `mull.yml`, then usually just:

```bash
./mull.sh mutate
```

If you change OpenSSL `config` flags or the Mull plugin path, run `./mull.sh compile` again (often incremental).

See [Supported Mutation Operators](https://mull.readthedocs.io/en/0.31.0/SupportedMutations.html).

---

## Reference (Mull tutorial)

Configure + build and run match the [Makefile integration tutorial](https://mull.readthedocs.io/en/0.31.0/tutorials/MakefileIntegration.html):

```bash
./config -O0 \
    -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
    -g -grecord-command-line
make build_generated -j
make ./test/bio_enc_test -j
mull-runner-18 ./test/bio_enc_test
```
