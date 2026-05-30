# OpenSSL tests via Ollama (operator guide)

See **`docs/llm-openssl-test-contract.md`** (full-module rules), **`docs/llm-openssl-test-snippet.md`** (body-only replacement rules), **`scripts/utils/gen-openssl-test-stub.sh`** (harness scaffolding).

Script **`scripts/utils/llm-openssl-test-context.sh`** assembles prompts in this order:

1. **WHY_YOU_ARE_HERE** — scenario / snippet hint  
2. **SOURCE_UNDER_TEST** — **`crypto/...`** file you extend (primary) — size via **`--impl-lines`** or **`--full-source`**  
3. **REFERENCE_TESTS** — excerpts from unrelated tests (style/API only; never your LLM scaffold) — tuned with **`--refs`**, **`--lines`**  
4. **RULES** — full contract or (**`--snippet`**) snippet contract only  
5. **WHAT_TO_EMIT**  

## Full module (single shot)

Emit a whole `.c` from the LLM:

```bash
./scripts/utils/llm-openssl-test-context.sh --task "scenario" [--impl-lines 350] [--refs 5] [--lines 80] PATH/UNDER/crypto/foo.c \\
  | ollama run qwen2.5-coder:7b --keepalive 0 > test/foo_llm_test.c
```

## Snippet workflow (recommended: harness script + tiny LLM output)

Use **`generated_test`** (already in **`test/build.info`** + **`test/recipes/90-test_bio_enc_generated.t`**) so you do not wire a new binary:

```bash
./scripts/utils/gen-openssl-test-stub.sh generated_test test_bio_enc_generated_smoke > test/generated_test.c

OLLAMA_MODEL=qwen2.5-coder:7b ./scripts/ollama-openssl-test.sh \\
  --into test/generated_test.c \\
  --snippet --impl-lines 400 --task "AES-256 CBC BIO round-trip vs fixed vectors" \\
  crypto/evp/bio_enc.c
```

**`--into`** runs Ollama in snippet mode and splices the model output between **`BEGIN_LLM_REPLACE`** and **`END_LLM_REPLACE`** in the stub (**`scripts/utils/fill-openssl-test-stub.sh`**). That script strips echoed marker lines, markdown fences, and ANSI terminal escapes from Ollama output before merging. No **`/tmp`** file or manual paste.

For a new test binary, generate the stub and register it in **`test/build.info`** + a recipe, then use the same **`--into`** pattern on that **`.c`** file.

Prompt-only (stdout, no splice):

```bash
OLLAMA_MODEL=qwen2.5-coder:7b ./scripts/ollama-openssl-test.sh --snippet --task "..." PATH/UNDER/crypto/foo.c > /tmp/snippet.txt
```

## Flags (all before **`PATH`**)

| Flag | Meaning |
|------|--------|
| `--into STUB.c` | (**`ollama-openssl-test.sh` only**) splice snippet output between **`BEGIN_LLM_REPLACE`** / **`END_LLM_REPLACE`** in **`STUB.c`** |
| `--snippet` | Snippet RULES doc; shorter default ref excerpts (`--lines` / `--refs` unless you override) |
| `--impl-lines N` | **`SOURCE_UNDER_TEST`** truncation (default 280); use **`--full-source`** for all |
| `--refs K` | How many reference test files |
| `--lines N` | Lines excerpted per reference file |
| `--task "…"` | Free-form scenario description |
| `--keywords a,b` | Pull extra **`test/*.c`** matches |

## Requirements

- **`bash`**, **`find`**, **`grep`**, **`head`**; optional **`rg`**
- **`ollama`** for **`scripts/ollama-openssl-test.sh`**
