"""Register standalone test binaries in test/build.info.

OpenSSL's build system only generates a compile rule (with the right
-I../include -I../apps/include flags) for source files that build.info knows
about. Adding a new test/<name>.c without a matching build.info entry means
`make` falls back to an implicit rule with no include path, and the build
fails with e.g. "openssl/bio.h file not found".

Registering a test adds the two things a new test binary needs:
  1. Its name in the PROGRAMS{...} test list (right after "generated_test").
  2. A SOURCE[name]=/INCLUDE[name]=/DEPEND[name]= block (modeled on the
     generated_test block).

`SOURCE[...]` is relative to test/, so a sweep-generated test living in
test/generated/<name>/<name>.c registers as `generated/<name>/<name>.c`.
INCLUDE/DEPEND are relative to test/ too, so they do not change with the
source's subdirectory.

Idempotent: safe to re-run; already-present entries are left alone. No
reconfigure is triggered here -- mull.sh's compile/compile-cov already re-run
`./config` on every build.
"""

import re

from . import paths

BUILD_INFO = paths.TEST_DIR / "build.info"

ANCHOR = "generated_test"


class BuildInfoError(Exception):
    """test/build.info could not be updated."""


def add_to_program_list(text: str, name: str) -> tuple:
    pattern = re.compile(r"(?<![\w])" + re.escape(ANCHOR) + r"(?![\w])")
    already = re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text)
    if already:
        return text, False

    match = pattern.search(text)
    if not match:
        raise BuildInfoError("could not find '{}' in {}".format(ANCHOR, BUILD_INFO))

    insert_at = match.end()
    return text[:insert_at] + " " + name + text[insert_at:], True


def add_build_block(text: str, name: str, source: str) -> tuple:
    if "SOURCE[{}]=".format(name) in text:
        return text, False

    anchor_block = re.search(
        r"  SOURCE\[{0}\]=.*\n  INCLUDE\[{0}\]=.*\n  DEPEND\[{0}\]=.*\n".format(
            re.escape(ANCHOR)
        ),
        text,
    )
    if not anchor_block:
        raise BuildInfoError(
            "could not find build block for '{}' in {}".format(ANCHOR, BUILD_INFO)
        )

    new_block = (
        "\n  SOURCE[{}]={}\n"
        "  INCLUDE[{}]=../include ../apps/include\n"
        "  DEPEND[{}]=../libcrypto libtestutil.a\n".format(name, source, name, name)
    )
    insert_at = anchor_block.end()
    return text[:insert_at] + new_block + text[insert_at:], True


def register(name: str, source: str = None) -> tuple:
    """Add `name` to test/build.info. Returns (list_added, block_added)."""
    source = source or "{}.c".format(name)

    if not BUILD_INFO.exists():
        raise BuildInfoError("{} not found".format(BUILD_INFO))

    text = BUILD_INFO.read_text()
    text, list_added = add_to_program_list(text, name)
    text, block_added = add_build_block(text, name, source)

    if list_added or block_added:
        BUILD_INFO.write_text(text)
    return list_added, block_added
