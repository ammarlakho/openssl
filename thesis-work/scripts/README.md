# OpenSSL Test Generation Scripts

Generate OpenSSL unit tests with an LLM over an OpenAI-compatible
chat-completions endpoint.

Everything lives behind one entry point, `llm_test.py`, backed by the `llmtest`
package. Python 3.9+, standard library only: no `curl`, `jq`, `rg`, or
third-party packages required.

```
llm_test.py            CLI entry point
llmtest/paths.py       repo / thesis directory resolution
llmtest/context.py     prompt assembly (source + reference tests + rules)
llmtest/stub.py        test .c skeleton generation and splicing
llmtest/backends.py    HTTP client for the chat-completions endpoint
llmtest/cli.py         argument parsing and command dispatch
llmtest/sweep.py       parameter sweeps: one saved test per grid point
llmtest/buildinfo.py   test/build.info registration
register_test.py       CLI wrapper around llmtest/buildinfo.py
```

Paths you pass are resolved against the repo root, so the commands below work
from any directory.

## Commands

| Command | Purpose |
|---------|---------|
| `generate` | Assemble a prompt, run a model, print or splice the result |
| `context`  | Print the assembled prompt without calling a model |
| `stub`     | Print a fresh test `.c` skeleton |
| `fill`     | Splice a generated body into an existing stub |
| `sweep`    | Run a grid of sampling parameters, saving one test per point |

## Workflow: snippet mode (recommended)

1. **Scaffold a stub** (once per test):

   ```bash
   ./thesis-work/scripts/llm_test.py stub generated_test test_bio_enc_smoke \
     --source crypto/evp/bio_enc.c > test/generated_test.c
   ```

   `--source` derives the stub's `#include`s from the API symbols the source
   under test actually uses, instead of assuming every test is a BIO/EVP one.

2. **Fill it with a model:**

   ```bash
   ./thesis-work/scripts/llm_test.py generate \
     --into test/generated_test.c \
     --snippet \
     --task "AES-256 CBC BIO round-trip vs fixed vectors" \
     crypto/evp/bio_enc.c
   ```

   `--into` splices the model output between the `BEGIN_LLM_REPLACE` and
   `END_LLM_REPLACE` markers in the stub, stripping echoed markers, markdown
   fences, and ANSI terminal escapes on the way in. In snippet mode `--into`
   doubles as `--stub`, so the stub is included in the prompt verbatim — the
   model can otherwise only guess which headers exist and what the function is
   called.

3. **Verify and compile.** For a brand new test binary, register it first with
   `register_test.py <name>`.

Run `generate` with no arguments at all to apply the default AES-256 scenario
above (snippet mode, `crypto/evp/bio_enc.c`, into `test/generated_test.c`).

## Workflow: parameter sweeps

`sweep` runs one generation per point of a sampling-parameter grid and saves
each result as a self-contained directory under `test/generated/`:

```
test/generated/<name>/
    <name>.c        the filled stub -- this is what the build compiles
    meta.json       model, endpoint, every sampling knob, timing, outcome
    prompt.txt      the exact prompt that was sent
    response.txt    the raw model reply, before splicing/sanitising
test/generated/runs.jsonl   one line per run, appended across sweeps
```

The name encodes the model, the knobs and a timestamp, so a directory listing
is already a readable result table:

```
gen_gpt_oss_120b_t0p8_tp0p95_fp0p3_s2_260826_193502
 |    |            |     |      |    |  |
 |    model        temp  top_p  freq |  run start (yymmdd_HHMMSS)
 prefix                        penalty seed
```

Only `[a-z0-9_]` is used, because the name is also a make target and a C
filename (`.` becomes `p`: `0.8` -> `0p8`). Each successful run is registered
in `test/build.info` with `SOURCE[<name>]=generated/<name>/<name>.c`, so
`make test/<name>` and `./mull.sh mutate ./test/<name>` work straight away.

Runs are independent: one failure is recorded in that run's `meta.json` and the
sweep carries on. Failed runs are not registered, and `sweep` exits non-zero if
any run failed.

### Running one

```bash
./thesis-work/scripts/llm_test.py sweep thesis-work/sweeps/bio_enc.json --dry-run
./thesis-work/scripts/llm_test.py sweep thesis-work/sweeps/bio_enc.json
```

`--dry-run` prints the planned runs and their names without calling the model
or writing anything -- worth doing first, since a full grid is a lot of runs.

### The config

Changing parameters is a config edit, not a code edit. Copy
`thesis-work/sweeps/bio_enc.json` and adjust:

```json
{
  "source": "crypto/evp/bio_enc.c",
  "task": "AES-256 CBC BIO round-trip vs fixed vectors",
  "test_fn": "test_bio_enc_generated",
  "prefix": "gen",
  "profile": "gptoss",
  "snippet": true,
  "repeats": 1,
  "sleep": 0,
  "context": { "refs": 4, "lines": 50, "keywords": [] },
  "grid": {
    "temperature": [0.2, 0.8, 1.0],
    "top_p": [0.95],
    "frequency_penalty": [0.0, 0.3],
    "seed": [1, 2, 3]
  }
}
```

`grid` is a full cartesian product (the example above is 3x1x2x3 = 18 runs).
Axes: `temperature`, `top_p`, `frequency_penalty`, `presence_penalty`,
`repetition_penalty`, `seed`, `max_tokens`, `reasoning_effort`. Omit an axis to
leave it at the server default. `repeats` re-runs every grid point N times
(useful for measuring run-to-run variance at a fixed temperature); the copies
get an `_rN` component in their names.

`test_fn` defaults to `test_<source stem>_generated`, and `context` takes the
prompt options below (`refs`, `lines`, `keywords`, `impl_lines`, `notes`).

### Sweep flags

| Flag | Meaning |
|------|---------|
| `--dry-run` | Print the planned runs; call no model, write nothing |
| `--grid AXIS=V1,V2` | Override one grid axis; repeatable |
| `--limit N` | Stop after N runs |
| `--repeats N` / `--sleep S` | Override the config |
| `--profile` / `--model` / `--api-url` | Override the endpoint |
| `--source` / `--task` / `--test-fn` / `--prefix` | Override the scenario |
| `--out-dir DIR` | Write somewhere other than `test/generated` |
| `--no-register` | Skip the `test/build.info` entries |

So a one-off variation needs no new config file:

```bash
./thesis-work/scripts/llm_test.py sweep thesis-work/sweeps/bio_enc.json \
  --profile gemma --grid temperature=0.7 --grid seed=1,2,3,4,5 --prefix gemma
```

## Full module (single shot)

Without `--snippet` the model emits a whole compilable `.c`:

```bash
./thesis-work/scripts/llm_test.py generate \
  --task "AES-256 CBC operations" \
  crypto/evp/bio_enc.c > test/bio_enc_test.c
```

## Endpoint

`generate` POSTs to an OpenAI-compatible chat-completions endpoint.

```bash
./thesis-work/scripts/llm_test.py generate --profile gemma \
  --into test/generated_test.c \
  --snippet --task "BIO cipher operations" crypto/evp/bio_enc.c
```

### Configuration

Copy `llm-movels.env.example` to `llm-models.env` (gitignored) and fill it in:

```bash
LLM_PROFILE=gptoss
GPTOSS_API_URL=http://host:11434/v1/chat/completions
GPTOSS_MODEL=gpt-oss:120b
GEMMA_API_URL=http://host:8000/v1/chat/completions
GEMMA_MODEL=RedHatAI/gemma-4-31B-it-FP8-Dynamic
```

If the endpoint needs a key, set `<PROFILE>_API_KEY` (or `API_KEY`); it is sent
as `Authorization: Bearer …`.

A profile named `foo` reads `FOO_API_URL` and `FOO_MODEL`, so adding a profile
is just two more lines — no code change. Resolution order, highest first:

1. `--api-url` / `--model` / `--profile` on the command line
2. `API_URL` / `LLM_MODEL` / `LLM_PROFILE` in the real environment
3. `<PROFILE>_API_URL` / `<PROFILE>_MODEL` from `llm-models.env`

Blank values in the env file are ignored rather than treated as set.

## Prompt options

Shared by `generate` and `context`:

| Flag | Meaning |
|------|---------|
| `--snippet` | Snippet rules doc; body-only output; shorter default excerpts |
| `--impl-lines N` | Truncate the source under test to its first N lines (default: no truncation) |
| `--full-source` | No-op, kept for compatibility: the whole source is the default |
| `--refs K` | Number of reference test files (default 5, or 4 with `--snippet`) |
| `--lines N` | Lines excerpted per reference file (default 120, or 50 with `--snippet`) |
| `--task "…"` | Free-form scenario description |
| `--keywords a,b` | Extra search terms when picking reference tests |
| `--notes` | List `NOTES*.md` at the repo root |
| `--stub PATH` | Show the model the stub it is filling (`generate` defaults to `--into`) |

## Sampling parameters

`generate` only. Unset flags are omitted from the request, so the server's own
defaults apply.

| Flag | Meaning |
|------|---------|
| `--temperature F` | Sampling temperature |
| `--top-p F` | Nucleus sampling |
| `--seed N` | Sampling seed, where the server honours it |
| `--max-tokens N` | Cap on generated tokens; raise if output comes back truncated |
| `--reasoning-effort low\|medium\|high` | Reasoning models (gpt-oss) |
| `--frequency-penalty F` | OpenAI repetition penalty, ~-2..2, 0 = off |
| `--presence-penalty F` | OpenAI presence penalty, ~-2..2, 0 = off |
| `--repetition-penalty F` | vLLM-only multiplicative penalty, ~1.0..2.0, 1.0 = off |

### A note on repetition penalties

There is no `repeat_penalty` field on either endpoint in `llm-models.env`:
that name belongs to llama.cpp and Ollama's *native* `/api/generate` options,
not to the OpenAI-compatible `/v1/chat/completions` route both profiles use.
The portable spelling is `frequency_penalty` -- Ollama's `/v1` layer maps it
onto llama.cpp's `repeat_penalty`, and vLLM implements it natively. vLLM also
accepts its own `repetition_penalty` as an extra top-level field; Ollama
ignores unknown fields, so sending it is harmless but has no effect there.
Prefer `frequency_penalty` for anything compared across both models.

`seed` is honoured by both servers; `reasoning_effort` only means something to
gpt-oss.

Token usage and a truncation warning are logged to stderr on every call.

`context` also takes `--contract-only` to print just the rules document.

## Prompt structure

`context.py` assembles, in order:

1. **WHY_YOU_ARE_HERE** — scenario and snippet-mode hint
2. **SOURCE_UNDER_TEST** — the `crypto/...` file being tested
3. **REFERENCE_TESTS** — short excerpts from other tests (style/API hints only)
4. **STUB** — snippet mode: the exact file being compiled
5. **RULES** — `docs/llm-openssl-test-contract.md`, or the snippet contract
6. **WHAT_TO_EMIT** — the output task

### Reference-test selection

Candidates are every `test/**/*.c` except:

- `test/helpers/` and `test/generated/`;
- anything that looks like this tool's own output — untracked, or named
  `*generated*`/`*llm*`, or still carrying an `LLM_REPLACE` marker;
- the in-tree test for the file under test — `test/<stem>_test.c` or
  `test/<stem>test.c`. It is substantially the answer to the question being
  asked, so it never appears as a reference. Only the exact stem is matched, so
  a module-wide test like `bntest.c` still serves as a reference for
  `bn_add.c`.

Each candidate is scored on two independent signals:

- **Content** — weighted BM25 over the source's stem, its two enclosing
  directory names, up to 20 public API symbols found in the source, and any
  `--keywords`. BM25 supplies length normalisation, so a 1500-line catch-all no
  longer outranks a focused test just by mentioning more symbols in passing,
  and IDF over the test corpus automatically discounts near-ubiquitous terms
  like `BIO_ctrl`.
- **Filename affinity** — how much the candidate's name looks like the
  source's, since a test body rarely spells out the file it exercises
  (`bio_enc` does not appear as a whole word anywhere inside
  `bio_enc_test.c`). Stem tokens are weighted by how rare they are across test
  filenames, so `x509` counts and `lib`/`int` do not.

Both are normalised to `[0, 1]` and combined as `content + W_NAME * name`, so
`W_NAME` in `context.py` reads directly as "a perfect name match is worth this
many times the best content match".

See `../docs/llm-openssl-operator.md` for the operator guide.
