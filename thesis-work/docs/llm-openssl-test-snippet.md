# Snippet-mode rules (stub already exists)

Operators generate **`setup_tests`, `ADD_TEST`, `#include`** with **`scripts/llm_test.py stub`** (or by hand).

The LLM fills **only the body** inside **`BEGIN_LLM_REPLACE` … `END_LLM_REPLACE`** in that stub.

## Forbidden

- **No further `#include`**, **`setup_tests`**, **`main`**, or **`ADD_TEST`** unless the stub is wrong.
- **No** `#include "crypto/...` or headers mirroring **`crypto/foo/bar.c` → `crypto/foo/bar.h`** (almost always hallucinated).
- Use **only `<openssl/*.h>`** names that already appear in **`include/openssl/`**, plus **`testutil.h`** semantics from references.

## Required

- Use **`TEST_*` macros only** (`TEST_true`, `TEST_ptr`, **`TEST_mem_eq(a, na, b, nb)`**, …). No `TEST_assert`.
- Replace **everything between** literal comments **`/* BEGIN_LLM_REPLACE */`** and **`/* END_LLM_REPLACE */`**, **including** the placeholder **`return TEST_true(1);`**.
- **`return 1`** on overall success and **`return 0`** when any **`TEST_*` check fails (same conventions as **`test/*.c`**).
- **Opaque types:** no `bio->internal`; use **`BIO_get_cipher_ctx`**, **`BIO_read`/`BIO_write`/`BIO_push`**, etc.

## Output shape

Plain C replacing the **`BEGIN_LLM_REPLACE`** … **`END_LLM_REPLACE`** block (markers stay in place or are removed manually after merge—as long as semantics match). Include all **`return`** paths the function needs—no stray markdown or prose.
