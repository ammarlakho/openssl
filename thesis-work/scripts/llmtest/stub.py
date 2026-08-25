"""Scaffold a test .c skeleton and splice model output into it."""

import datetime
import re
import sys
from pathlib import Path
from typing import List

BEGIN_MARKER = "/* BEGIN_LLM_REPLACE */"
END_MARKER = "/* END_LLM_REPLACE */"

TEST_FN_RE = re.compile(r"^test_[A-Za-z0-9_]+$")

STUB_TEMPLATE = """/*
 * Copyright %(year)s The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: %(prog)s.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "testutil.h"

static int %(func)s(void)
{
    %(begin)s
    return TEST_true(1);
    %(end)s
}

int setup_tests(void)
{
    ADD_TEST(%(func)s);
    return 1;
}
"""

# Ollama's CLI interleaves spinner/cursor escapes with the model output.
ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_BARE_MARKERS = frozenset({"BEGIN_LLM_REPLACE", "END_LLM_REPLACE"})
_COMMENT_MARKER_RE = re.compile(r"^/\*\s*(?:BEGIN|END)_LLM_REPLACE\s*\*/$")


class StubError(Exception):
    """A stub could not be generated or filled."""


def generate_stub(prog: str, func: str) -> str:
    """Return a compilable OpenSSL test skeleton for test function `func`."""
    if not TEST_FN_RE.match(func):
        raise StubError("test_fn_name should look like test_foo ({})".format(func))
    return STUB_TEMPLATE % {
        "year": datetime.date.today().year,
        "prog": prog,
        "func": func,
        "begin": BEGIN_MARKER,
        "end": END_MARKER,
    }


def sanitize_body(body: str) -> str:
    """Strip the artifacts models and terminals add around generated code.

    Removes ANSI escapes, CRs, markdown fences, and any replace markers the
    model helpfully echoed back at us.
    """
    body = ANSI_OSC.sub("", body)
    body = ANSI_CSI.sub("", body)
    body = body.replace("\r", "")

    kept: List[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped in _BARE_MARKERS or _COMMENT_MARKER_RE.match(stripped):
            continue
        if stripped.startswith("```"):
            continue
        kept.append(line)
    return "\n".join(kept)


def fill_stub(stub_path: Path, body: str) -> None:
    """Replace everything between the markers in `stub_path` with `body`."""
    if not stub_path.is_file():
        raise StubError("stub not found: {}".format(stub_path))

    text = stub_path.read_text()
    if "BEGIN_LLM_REPLACE" not in text:
        raise StubError("missing BEGIN_LLM_REPLACE in {}".format(stub_path))
    if "END_LLM_REPLACE" not in text:
        raise StubError("missing END_LLM_REPLACE in {}".format(stub_path))

    clean = sanitize_body(body)

    out: List[str] = []
    skipping = False
    for line in text.splitlines():
        if not skipping and BEGIN_MARKER in line:
            out.append(line)
            out.extend(clean.splitlines())
            skipping = True
            continue
        if skipping:
            if END_MARKER in line:
                skipping = False
                out.append(line)
            continue
        out.append(line)

    stub_path.write_text("\n".join(out) + "\n")


def read_body(source: str) -> str:
    """Read a generated body from a file path, or from stdin for '-'."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise StubError("body file not found: {}".format(path))
    return path.read_text(errors="replace")
