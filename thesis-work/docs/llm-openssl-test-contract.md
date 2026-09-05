# OpenSSL LLM test generation contract

Stable rules for generating a **new** OpenSSL unit-test `.c`.

Prefer splitting work: scaffold **`includes`**, **`setup_tests`**, **`ADD_TEST`** locally (script **`scripts/llm_test.py stub`** or by hand); run **`scripts/llm_test.py context --snippet`** so the LLM replaces only **`BEGIN_LLM_REPLACE` … `END_LLM_REPLACE`** (see **`docs/llm-openssl-test-snippet.md`**).

Prompt bundles place **implementation (`SOURCE_UNDER_TEST`) first**, then short **REFERENCE_TESTS** for style—they are **not** the finished test binary you are authoring.

*(Operator workflow: **`docs/llm-openssl-operator.md`**.)*

## Forbidden includes and symbols

- **Never** `#include "crypto/...`**, **`internal/...`** (unless an existing test in-tree already uses that exact header for the same scenario).
- Never invent **`crypto/<path>/<base>.h`** paired to **`crypto/<path>/<base>.c`**.
- Prefer **`<openssl/foo.h>`** from **`include/openssl/`** and **`testutil.h`**.


## Role

Produce **one** `.c` file (or a minimal diff-shaped answer) that compiles as an OpenSSL test program linked with **libcrypto** and **libtestutil**, following patterns in `test/*.c`.

## Harness (required)

- Implement **`int setup_tests(void)`**.
- Register cases with **`ADD_TEST(static_fn)`** or **`ADD_ALL_TESTS(static_fn, n)`** (or `ADD_ALL_TESTS_NOSUBTEST` when appropriate).
- Return **`1`** from `setup_tests` on successful registration, **`0`** on failure (see `test/testutil.h` comments).
- Each test is **`static int test_<name>(void)`** (or `static int test_<name>(int idx)` for parameterized tests).
- Return **`1`** if the test passed, **`0`** if any assertion failed.
- Optional: **`void cleanup_tests(void)`** if resources must be released globally.

Do **not** write your own `main`; the test driver supplies it.

## Headers

- Prefer **public** `<openssl/*.h>` and **`#include "testutil.h"`**.
- Use **`#include <string.h>`**, **`#include <stdlib.h>`**, etc. as needed.
- Follow **Forbidden includes** above (**`internal/`** only when an existing in-tree test does the same for the same scenario).

## Assertions (`testutil.h`)

Use **only** real macros, for example:

- **`TEST_true(expr)`**, **`TEST_false(expr)`**
- **`TEST_ptr(ptr)`**, **`TEST_ptr_null(ptr)`**
- **`TEST_int_eq`**, **`TEST_int_ne`**, **`TEST_int_gt`**, **`TEST_long_*`**, **`TEST_size_t_*`**, **`TEST_uchar_eq`**, etc.
- **`TEST_mem_eq(a, a_len, b, b_len)`** — **four** arguments; lengths are **`size_t`** (cast if needed).
- **`TEST_str_eq`**, **`TEST_mem_ne`**, etc.

There is **no** `TEST_assert`. Do not invent macro names.

## Types and APIs

- Treat library objects as **opaque** unless the public header exposes fields (`BIO`, `SSL`, `EVP_PKEY`, …). Use documented accessors (`BIO_get_cipher_ctx`, `EVP_*`, …)—never `ptr->internal_field` through incomplete types.
- Call **real** library functions only (OpenSSL + C standard library + POSIX where already used in tests).

## Style

- Match surrounding tests: early **`goto err`** with **`BIO_free_all`** / **`OPENSSL_free`** patterns where appropriate.
- Use **fixed test vectors** when possible (deterministic); use **`RAND_bytes`** only with **`#include <openssl/rand.h>`** and **`TEST_int_gt(RAND_bytes(...), 0)`** (or equivalent).
- Include the standard OpenSSL **Apache 2.0** file header with copyright line.

## Recipe / build (out of scope for the `.c` file only)

New binaries need entries in **`test/build.info`** and a recipe under **`test/recipes/`**. If you are asked to output only `.c`, mention that the operator must wire the target—do not invent recipe names that collide with existing `setup()` names in Perl tests.

## Output format

When asked for minimal output: **only valid C** for the test source file—no markdown fences, no narrative, no ANSI escape sequences or stray tokens.
