# OpenSSL Test Generation Scripts

This directory contains scripts for generating OpenSSL unit tests using LLM models via Ollama or remote APIs.

## User-Facing Scripts

### `ollama-openssl-test-remote.sh`

Generate OpenSSL unit tests using a remote OpenAI-compatible LLM API (gptoss, Gemma API, or other compatible endpoints).

**Usage:**
```bash
./ollama-openssl-test-remote.sh [--profile gptoss|gemma] [--into STUB.c] [OPTIONS] PATH/UNDER/crypto/foo.c
```

**Environment variables:**

Copy `llm-models.env.example` to `llm-models.env` and fill in the empty values.

**Example:**
```bash
LLM_PROFILE=gptoss GPTOSS_API_URL=http://localhost:11434/api/chat \
  GPTOSS_MODEL=qwen2.5-coder:7b ./ollama-openssl-test-remote.sh \
  --into test/generated_test.c \
  --snippet --task "BIO cipher operations" \
  crypto/evp/bio_enc.c
```


### `ollama-openssl-test.sh`

Generate OpenSSL unit tests locally using Ollama with an LLM model.

**Usage:**
```bash
OLLAMA_MODEL=qwen2.5-coder:7b ./ollama-openssl-test.sh [OPTIONS] PATH/UNDER/crypto/foo.c
```

**Common options:**
- `--into STUB.c` — Splice LLM output into an existing test stub between `BEGIN_LLM_REPLACE` and `END_LLM_REPLACE` markers
- `--snippet` — Generate only the test body (snippet mode); use with a pre-generated stub
- `--impl-lines N` — Limit source file to first N lines (default: 280)
- `--task "..."` — Free-form scenario description for the LLM
- `--refs K` — Number of reference test files to include (default: 3)
- `--lines N` — Lines per reference file (default: 20)

**Example: Generate a complete test**
```bash
OLLAMA_MODEL=qwen2.5-coder:7b ./ollama-openssl-test.sh \
  --task "AES-256 CBC operations" \
  crypto/evp/bio_enc.c > test/bio_enc_test.c
```

**Example: Fill an existing stub**
```bash
./scripts/utils/gen-openssl-test-stub.sh generated_test test_bio_enc_smoke > test/generated_test.c

OLLAMA_MODEL=qwen2.5-coder:7b ./ollama-openssl-test.sh \
  --into test/generated_test.c \
  --snippet --impl-lines 400 \
  --task "AES-256 CBC BIO round-trip vs fixed vectors" \
  crypto/evp/bio_enc.c
```

## Internal Helper Scripts (under `utils/`)

These scripts support the user-facing tools. You typically do not call them directly:

- **`gen-openssl-test-stub.sh`** — Scaffold a new test `.c` file with boilerplate (`main`, `ADD_TEST` calls, includes)
- **`fill-openssl-test-stub.sh`** — Splice LLM-generated code into a stub, handling markdown fences and ANSI escapes
- **`llm-openssl-test-context.sh`** — Assemble the full prompt for the LLM (source code + references + rules + scenario)

## Workflow: Snippet Mode (Recommended)

1. **Generate a stub** (once per test):
   ```bash
   ./scripts/utils/gen-openssl-test-stub.sh test_name test_label > test/test_name.c
   ```

2. **Run Ollama to fill the stub:**
   ```bash
   OLLAMA_MODEL=qwen2.5-coder:7b ./ollama-openssl-test.sh \
     --into test/test_name.c \
     --snippet --impl-lines 400 \
     --task "your scenario description" \
     crypto/evp/your_source.c
   ```

3. **Verify and compile** — the stub now contains LLM-generated test logic between markers

See `../docs/llm-openssl-ollama.md` for detailed documentation.

## Requirements

- **bash**, **find**, **grep**, **head**
- **ollama** (for `ollama-openssl-test.sh`) — https://ollama.ai
- **curl**, **jq** (for `ollama-openssl-test-remote.sh`)

## Configuration

### Local Ollama

Set `OLLAMA_MODEL` in your environment:
```bash
export OLLAMA_MODEL=qwen2.5-coder:7b
```

The `ollama` command must be in your `PATH` and the service running (default: `http://localhost:11434`).

### Remote API (gptoss)

Create or edit `../llm-models.env`:
```bash
LLM_PROFILE=gptoss
GPTOSS_API_URL=http://localhost:11434/api/chat
GPTOSS_MODEL=qwen2.5-coder:7b
```

Or pass variables directly:
```bash
API_URL=http://your-api:port/chat LLM_MODEL=model-name ./ollama-openssl-test-remote.sh ...
```
