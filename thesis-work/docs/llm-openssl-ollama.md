# OpenSSL tests via an LLM (operator guide)

See **`docs/llm-openssl-test-contract.md`** (full-module rules), **`docs/llm-openssl-test-snippet.md`** (body-only replacement rules), **`scripts/README.md`** (full CLI reference).

Everything runs through **`scripts/llm_test.py`** (Python 3.9+, stdlib only). It assembles prompts in this order:

1. **WHY_YOU_ARE_HERE** — scenario / snippet hint
2. **SOURCE_UNDER_TEST** — **`crypto/...`** file you extend (primary) — size via **`--impl-lines`** or **`--full-source`**
3. **REFERENCE_TESTS** — excerpts from unrelated tests (style/API only; never your LLM scaffold) — tuned with **`--refs`**, **`--lines`**
4. **RULES** — full contract or (**`--snippet`**) snippet contract only
5. **WHAT_TO_EMIT**

## Full module (single shot)

Emit a whole `.c` from the LLM:

```bash
./scripts/llm_test.py generate --task "scenario" \
  [--impl-lines 350] [--refs 5] [--lines 80] PATH/UNDER/crypto/foo.c \
  > test/foo_llm_test.c
```

To inspect the prompt without spending a model call, swap `generate` for `context`.

## Snippet workflow (recommended: harness script + tiny LLM output)

Use **`generated_test`** (already in **`test/build.info`** + **`test/recipes/90-test_bio_enc_generated.t`**) so you do not wire a new binary:

```bash
./scripts/llm_test.py stub generated_test test_bio_enc_generated_smoke \
  > test/generated_test.c

./scripts/llm_test.py generate \
  --into test/generated_test.c \
  --snippet --impl-lines 400 --task "AES-256 CBC BIO round-trip vs fixed vectors" \
  crypto/evp/bio_enc.c
```

**`--into`** splices the model output between **`BEGIN_LLM_REPLACE`** and **`END_LLM_REPLACE`** in the stub, stripping echoed marker lines, markdown fences, and ANSI terminal escapes first. No **`/tmp`** file or manual paste.

For a new test binary, generate the stub, register it with **`scripts/register_test.py <name>`** and add a recipe, then use the same **`--into`** pattern on that **`.c`** file.

Prompt-only (stdout, no splice):

```bash
./scripts/llm_test.py generate --snippet --task "..." PATH/UNDER/crypto/foo.c > /tmp/snippet.txt
```

## Backends

| Flag | Behaviour |
|------|-----------|
| `--backend ollama` | Shells out to `ollama run`; model from `--model`, `$OLLAMA_MODEL`, else `qwen2.5-coder:7b` |
| `--backend remote` (default) | POSTs to an OpenAI-compatible endpoint; `--profile gptoss\|gemma\|…` selects `<PROFILE>_API_URL` / `<PROFILE>_MODEL` from **`llm-models.env`** |

## Flags

| Flag | Meaning |
|------|--------|
| `--into STUB.c` | (**`generate` only**) splice output between **`BEGIN_LLM_REPLACE`** / **`END_LLM_REPLACE`** in **`STUB.c`** |
| `--snippet` | Snippet RULES doc; shorter default ref excerpts (`--lines` / `--refs` unless you override) |
| `--impl-lines N` | **`SOURCE_UNDER_TEST`** truncation (default 280); use **`--full-source`** for all |
| `--refs K` | How many reference test files |
| `--lines N` | Lines excerpted per reference file |
| `--task "…"` | Free-form scenario description |
| `--keywords a,b` | Pull extra **`test/*.c`** matches |

## Requirements

- **Python 3.9+** (standard library only)
- **`ollama`** on **`PATH`** for **`--backend ollama`**
- Network reach to the configured endpoint for **`--backend remote`**
