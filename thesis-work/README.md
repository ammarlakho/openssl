# LLM-generated unit tests for OpenSSL, scored by mutation testing

This directory holds the tooling for a master's thesis on generating OpenSSL
unit tests with an LLM and measuring them with mutation testing. It is a
working tree, not a library: the goal is that someone can re-run the
experiments, not that they can import anything.

It lives inside a fork of OpenSSL because the pipeline needs the real thing —
a generated test is compiled into OpenSSL's own build, run through OpenSSL's
test harness, and scored by mutating OpenSSL's source. The branch is
`mull-openssl-3.5.6`; everything outside `thesis-work/` is upstream OpenSSL
except one added test stub (`test/generated_test.c`) and its recipe.

**This is a workbench, not a results archive.** The analysis and the numbers
it produced live in the thesis report; what is here is the machinery that
produced them, so someone can point it at a source file and generate their own.
No generated test is committed — see *What is deliberately not here* below.

## Layout

```
mull-mutation/    Docker image + driver script for running Mull over OpenSSL
scripts/          the generation/scoring pipeline (Python 3.9+, stdlib only)
docs/             the prompt contracts the pipeline loads at run time
experiments/      experiment inputs, and the append-only record of every run
```

Each of `mull-mutation/` and `scripts/` has its own README with the full
command reference. `scripts/README.md` is the main one.

### `scripts/`

One entry point, `llm_test.py`, over a package:

| Module | Role |
|---|---|
| `paths.py` | repo / thesis directory resolution |
| `context.py` | prompt assembly: source, reference tests, rules |
| `stub.py` | test `.c` skeleton generation and splicing |
| `backends.py` | HTTP client for an OpenAI-compatible endpoint |
| `cli.py` | argument parsing and command dispatch |
| `experiment.py` | one saved test per point of a sampling grid |
| `mutation.py` | running Mull over generated tests, and scoring them |
| `mutants.py` | parsing Mull reports; mutant clustering and triage |
| `arms.py` | the three scoping-vs-implementation arms |
| `analysis.py` | joining runs to reports; the result tables |
| `buildinfo.py` | registering a new test binary in `test/build.info` |

No third-party packages, no `curl`, `jq` or `rg`. Paths given on the command
line resolve against the repo root, so the commands work from any directory.

### `docs/`

Not background reading — `paths.py` loads two of these files into every
prompt, so they are as much a part of the pipeline as the Python is.

| File | Role |
|---|---|
| `llm-openssl-test-contract.md` | rules for generating a whole test `.c` |
| `llm-openssl-test-snippet.md` | rules for body-only replacement (the mode actually used) |
| `llm-openssl-operator.md` | operator guide: how a run is assembled end to end |

### `experiments/`

```
configs/   experiment definitions: source under test, model, grid, seeds
triage/    hand-classified mutant verdicts (see scripts/README.md)
arms/      the arm-1 scenario corpus and its hand classification
results/   results.jsonl + results.csv, one row per run, append-only
```

`configs/`, `triage/` and `arms/` are inputs. `triage/bio_enc.json` is the
main hand-made artefact: a classification of every surviving mutant in
`crypto/evp/bio_enc.c`, each with the argument for its verdict, used to fix
the denominator that scores are computed against. `arms/scenarios_*.json` is
arm 1's stage-1 output — what the model said was worth testing, before any
test existed — which arm 2 and `arms-report` both consume; re-running the
model would not reproduce it, so it is committed rather than regenerated.

`results/results.jsonl` and `results.csv` are the record of every run behind
the thesis: parameters, outcome, and both scores, one row per run. The bulky
part of a run — Mull's full per-mutant report, plus build and Mull logs, tens
of MB per batch — is gitignored, so `experiments/results/<name>/` directories
are absent from a fresh checkout.

That has a consequence worth knowing before you try to reproduce a table:

- `mutation-report` reads only `results.csv` / `results.jsonl`, so it works on
  a fresh checkout with no endpoint, no Docker and no mutation run.
- `arms-report` joins each run to its per-mutant Mull report to decide *which*
  mutants a test killed, so it needs those per-run directories. On a fresh
  checkout it prints empty tables. Reproducing the arm tables means re-running
  `mutate` to rebuild the reports.

## What is deliberately not here

**No generated tests.** The experiments produced roughly 590 `.c` files — one
per (arm, seed, sampling point) — and none of them are committed. They are
gitignored, along with the per-run prompt/response captures under
`test/generated/` and Mull's full per-mutant reports under
`experiments/results/<name>/`.

That is a deliberate choice about what this tree is for. Three reasons:

1. **They are output, not source.** Every one is reproducible by running the
   pipeline; none was written by hand. Committing them would archive the
   answer instead of the method.
2. **They would bury the actual contribution.** Dropped into `test/` beside
   OpenSSL's own suite, 590 machine-named files and their ~1700 lines of
   `test/build.info` registrations make the diff against upstream unreadable.
   The interesting diff is `thesis-work/` plus one stub; it should stay that
   way.
3. **Size.** The `.c` files alone are ~3 MB; with the run captures and Mull
   reports a full batch is tens of MB more.

So a fresh checkout is a working pipeline with an empty output tree. Running
it will start filling `test/` with generated tests and
`experiments/results/<name>/` with reports — both already gitignored, so a
reproduction run leaves your own working tree as clean as you found it.

What *is* committed is everything an experiment needs as input — the prompt
contracts in `docs/`, the configs, the mutant triage, the arm-1 scenario
corpus — plus `results.csv` / `results.jsonl`, the flat one-row-per-run record
of what every generation scored. That record is small (~1 MB) and is what
makes `mutation-report` runnable without an endpoint or Docker.

## Running it

### 1. Mutation testing only

Needs Docker. No LLM endpoint required — this scores the hand-written
`test/bio_enc_test.c`, which is the baseline every generated test is compared
to.

```bash
./thesis-work/mull-mutation/mull.sh build          # toolchain image, once
./thesis-work/mull-mutation/mull.sh run-cov ./test/bio_enc_test
```

`compile-cov` is the mode that matters: without coverage instrumentation Mull
mutates all of libcrypto (~1600 mutants) rather than only what the test
reaches (~50). See `mull-mutation/README.md`.

### 2. Generation

Needs an OpenAI-compatible `/v1/chat/completions` endpoint. Copy the example
and fill it in:

```bash
cp thesis-work/llm-models.env.example thesis-work/llm-models.env
$EDITOR thesis-work/llm-models.env      # gitignored; may hold an API key
```

The thesis used `gpt-oss:120b` and `RedHatAI/gemma-4-31B-it-FP8-Dynamic` on a self-hosted vLLM
server. Any endpoint speaking the same protocol works; a Claude Code backend
is also supported (`backends.py`). Then:

```bash
# assemble a prompt and look at it, without calling anything
./thesis-work/scripts/llm_test.py context --snippet crypto/evp/bio_enc.c

# generate one test into the stub
./thesis-work/scripts/llm_test.py generate --into test/generated_test.c \
    --snippet crypto/evp/bio_enc.c
```

### 3. A full experiment

```bash
./thesis-work/scripts/llm_test.py experiment thesis-work/experiments/configs/bio_enc.json
./thesis-work/scripts/llm_test.py mutate --all
./thesis-work/scripts/llm_test.py mutation-report
```

### 4. The scoping-vs-implementation arms

The main experiment: three arms differing only in the task string given to the
model. Setup and flags are in `scripts/README.md` under *The
scoping-vs-implementation arms*.

```bash
./thesis-work/scripts/llm_test.py scenarios --source crypto/evp/bio_enc.c --seeds 1-50
./thesis-work/scripts/llm_test.py arm 1 thesis-work/experiments/configs/bio_enc_arms.json --scenarios …
./thesis-work/scripts/llm_test.py arm 2 thesis-work/experiments/configs/bio_enc_arms.json --triage …
./thesis-work/scripts/llm_test.py arms-report --source crypto/evp/bio_enc.c …
```

`arms-report` joins the run records to the per-mutant Mull reports and the
triage. It needs `experiments/results/<name>/` present, so run `mutate` first
(step 3) — the committed `results.csv` alone is not enough for these tables.

## Notes for a reader

- A generated test's `.c` sits flat in `test/` rather than in a subdirectory:
  `#include "testutil.h"` resolves relative to the file, and `build.info`'s
  `INCLUDE` cannot override that.
- A new test binary needs a `test/build.info` entry or the build falls back to
  an implicit rule with no include path. `register_test.py` adds one; it
  anchors on the `generated_test` entry, which is why that stub is committed.
- Sampling knobs are unset by default, so the endpoint's own defaults apply.
  Temperature was measured to have no effect on mutation score here
  (r = +0.03, p = 0.84), so pinning one would only create a number needing a
  justification.
