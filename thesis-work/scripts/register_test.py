#!/usr/bin/env python3
"""
Register a new standalone test binary in test/build.info.

OpenSSL's build system only generates a compile rule (with the right
-I../include -I../apps/include flags) for source files that build.info
knows about. Adding a new test/<name>.c without a matching build.info
entry means `make` falls back to an implicit rule with no include
path, and the build fails with e.g. "openssl/bio.h file not found".

This script adds the two things a new test binary needs:
  1. Its name in the PROGRAMS{...} test list (right after "generated_test").
  2. A SOURCE[name]=/INCLUDE[name]=/DEPEND[name]= block (modeled on the
     generated_test block).

Idempotent: safe to re-run; already-present entries are left alone.
No reconfigure is triggered here -- mull.sh's compile/compile-cov
already re-run `./config` on every build.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_INFO = REPO_ROOT / "test" / "build.info"

ANCHOR = "generated_test"


def add_to_program_list(text: str, name: str) -> tuple[str, bool]:
    pattern = re.compile(r"(?<![\w])" + re.escape(ANCHOR) + r"(?![\w])")
    already = re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text)
    if already:
        return text, False

    match = pattern.search(text)
    if not match:
        raise SystemExit(f"error: could not find '{ANCHOR}' in {BUILD_INFO}")

    insert_at = match.end()
    new_text = text[:insert_at] + " " + name + text[insert_at:]
    return new_text, True


def add_build_block(text: str, name: str, source: str) -> tuple[str, bool]:
    if f"SOURCE[{name}]=" in text:
        return text, False

    anchor_block = re.search(
        rf"  SOURCE\[{re.escape(ANCHOR)}\]=.*\n"
        rf"  INCLUDE\[{re.escape(ANCHOR)}\]=.*\n"
        rf"  DEPEND\[{re.escape(ANCHOR)}\]=.*\n",
        text,
    )
    if not anchor_block:
        raise SystemExit(f"error: could not find build block for '{ANCHOR}' in {BUILD_INFO}")

    new_block = (
        f"\n  SOURCE[{name}]={source}\n"
        f"  INCLUDE[{name}]=../include ../apps/include\n"
        f"  DEPEND[{name}]=../libcrypto libtestutil.a\n"
    )
    insert_at = anchor_block.end()
    new_text = text[:insert_at] + new_block + text[insert_at:]
    return new_text, True


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(f"usage: {sys.argv[0]} <test-name> [source.c]", file=sys.stderr)
        sys.exit(1)

    name = sys.argv[1]
    source = sys.argv[2] if len(sys.argv) == 3 else f"{name}.c"

    if not BUILD_INFO.exists():
        raise SystemExit(f"error: {BUILD_INFO} not found")

    text = BUILD_INFO.read_text()

    text, list_added = add_to_program_list(text, name)
    text, block_added = add_build_block(text, name, source)

    if not list_added and not block_added:
        print(f"'{name}' is already registered in {BUILD_INFO}; nothing to do.")
        return

    BUILD_INFO.write_text(text)

    if list_added:
        print(f"added '{name}' to the test program list")
    if block_added:
        print(f"added SOURCE/INCLUDE/DEPEND block for '{name}' (source: {source})")
    print(f"updated {BUILD_INFO}")
    print("run a compile/compile-cov (which re-runs ./config) to pick this up")


if __name__ == "__main__":
    main()
