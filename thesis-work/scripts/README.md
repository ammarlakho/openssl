# OpenSSL Test Generation Scripts

Generate OpenSSL unit tests with an LLM — either a local Ollama install or a
remote OpenAI-compatible endpoint.

Everything lives behind one entry point, `llm_test.py`, backed by the `llmtest`
package. Python 3.9+, standard library only: no `curl`, `jq`, `rg`, or
third-party packages required.

```
llm_test.py            CLI entry point
llmtest/paths.py       repo / thesis directory resolution
llmtest/context.py     prompt assembly (source + reference tests + rules)
llmtest/stub.py        test .c skeleton generation and splicing
llmtest/backends.py    local Ollama and remote HTTP backends
llmtest/cli.py         argument parsing and command dispatch
register_test.py       register a new test binary in test/build.info
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

## Workflow: snippet mode (recommended)

1. **Scaffold a stub** (once per test):

   ```bash
   ./thesis-work/scripts/llm_test.py stub generated_test test_bio_enc_smoke \
     > test/generated_test.c
   ```

2. **Fill it with a model:**

   ```bash
   ./thesis-work/scripts/llm_test.py generate \
     --into test/generated_test.c \
     --snippet --impl-lines 400 \
     --task "AES-256 CBC BIO round-trip vs fixed vectors" \
     crypto/evp/bio_enc.c
   ```

   `--into` splices the model output between the `BEGIN_LLM_REPLACE` and
   `END_LLM_REPLACE` markers in the stub, stripping echoed markers, markdown
   fences, and ANSI terminal escapes on the way in.

3. **Verify and compile.** For a brand new test binary, register it first with
   `register_test.py <name>`.

Run `generate` with no arguments at all to apply the default AES-256 scenario
above (snippet mode, `crypto/evp/bio_enc.c`, into `test/generated_test.c`).

## Full module (single shot)

Without `--snippet` the model emits a whole compilable `.c`:

```bash
./thesis-work/scripts/llm_test.py generate \
  --task "AES-256 CBC operations" \
  crypto/evp/bio_enc.c > test/bio_enc_test.c
```

## Backends

`--backend ollama` shells out to `ollama run`. The model comes
from `--model`, else `$OLLAMA_MODEL`, else `qwen2.5-coder:7b`.

```bash
OLLAMA_MODEL=qwen2.5-coder:7b ./thesis-work/scripts/llm_test.py generate \
  --snippet --task "BIO cipher operations" crypto/evp/bio_enc.c
```

`--backend remote` (the default) POSTs to an OpenAI-compatible chat-completions endpoint
(Ollama's native `/api/chat` response shape is also accepted).

```bash
./thesis-work/scripts/llm_test.py generate --backend remote --profile gemma \
  --into test/generated_test.c \
  --snippet --task "BIO cipher operations" crypto/evp/bio_enc.c
```

### Remote configuration

Copy `llm-movels.env.example` to `llm-models.env` (gitignored) and fill it in:

```bash
LLM_PROFILE=gptoss
GPTOSS_API_URL=http://host:11434/v1/chat/completions
GPTOSS_MODEL=gpt-oss:120b
GEMMA_API_URL=http://host:8000/v1/chat/completions
GEMMA_MODEL=RedHatAI/gemma-4-31B-it-FP8-Dynamic
```

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
| `--impl-lines N` | Truncate the source under test (default 280) |
| `--full-source` | Include the whole source file instead |
| `--refs K` | Number of reference test files (default 5, or 4 with `--snippet`) |
| `--lines N` | Lines excerpted per reference file (default 120, or 50 with `--snippet`) |
| `--task "…"` | Free-form scenario description |
| `--keywords a,b` | Extra search terms when picking reference tests |
| `--notes` | List `NOTES*.md` at the repo root |

`context` also takes `--contract-only` to print just the rules document.

## Prompt structure

`context.py` assembles, in order:

1. **WHY_YOU_ARE_HERE** — scenario and snippet-mode hint
2. **SOURCE_UNDER_TEST** — the `crypto/...` file being tested
3. **REFERENCE_TESTS** — short excerpts from other tests (style/API hints only)
4. **RULES** — `docs/llm-openssl-test-contract.md`, or the snippet contract
5. **WHAT_TO_EMIT** — the output task

Reference tests are picked by scanning `test/**/*.c` for the source file's
stem, its two enclosing directory names, up to 20 public API symbols found in
the source (`BIO_*`, `EVP_*`, `SSL_*`, …), and any `--keywords`. Files are
ranked by how many of those terms they match. Previously generated tests are
excluded so the model never sees its own output as a reference.

See `../docs/llm-openssl-ollama.md` for the operator guide.
