"""Scaffold a test .c skeleton and splice model output into it."""

import datetime
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import paths

BEGIN_MARKER = "/* BEGIN_LLM_REPLACE */"
END_MARKER = "/* END_LLM_REPLACE */"

TEST_FN_RE = re.compile(r"^test_[A-Za-z0-9_]+$")

# Symbol prefix -> public header. Used to give a stub the includes the source
# under test actually implies, instead of assuming every test is a BIO/EVP one.
# Longest prefix wins, and the header must exist in include/openssl/.
SYMBOL_HEADERS = (
    ("OSSL_PARAM", "params.h"),
    ("OSSL_ENCODER", "encoder.h"),
    ("OSSL_DECODER", "decoder.h"),
    ("OSSL_PROVIDER", "provider.h"),
    ("OSSL_STORE", "store.h"),
    ("OSSL_HTTP", "http.h"),
    ("OSSL_CMP", "cmp.h"),
    ("EVP", "evp.h"),
    ("BIO", "bio.h"),
    ("SSL", "ssl.h"),
    ("RSA", "rsa.h"),
    ("DSA", "dsa.h"),
    ("DH", "dh.h"),
    ("EC", "ec.h"),
    ("ECDSA", "ecdsa.h"),
    ("BN", "bn.h"),
    ("ASN1", "asn1.h"),
    ("X509V3", "x509v3.h"),
    ("X509", "x509.h"),
    ("PEM", "pem.h"),
    ("PKCS7", "pkcs7.h"),
    ("PKCS12", "pkcs12.h"),
    ("CMS", "cms.h"),
    ("OCSP", "ocsp.h"),
    ("HMAC", "hmac.h"),
    ("CMAC", "cmac.h"),
    ("KDF", "kdf.h"),
    ("RAND", "rand.h"),
    ("ERR", "err.h"),
    ("CONF", "conf.h"),
    ("SHA", "sha.h"),
    ("MD5", "md5.h"),
    ("AES", "aes.h"),
    ("DES", "des.h"),
    ("CRYPTO", "crypto.h"),
    ("OPENSSL", "crypto.h"),
)

# Always present: a test needs the harness, and string.h is used by nearly
# every test body for memcpy/memcmp.
BASE_INCLUDES = ("<string.h>",)
MAX_DERIVED_INCLUDES = 6

SYMBOL_SCAN_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)_[A-Za-z0-9_]+\b")


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

%(includes)s

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

# Guards against bodies pasted in from a terminal, which carry escapes.
ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_BARE_MARKERS = frozenset({"BEGIN_LLM_REPLACE", "END_LLM_REPLACE"})
_COMMENT_MARKER_RE = re.compile(r"^/\*\s*(?:BEGIN|END)_LLM_REPLACE\s*\*/$")


class StubError(Exception):
    """A stub could not be generated or filled."""


def _header_exists(header: str) -> bool:
    base = paths.REPO_ROOT / "include" / "openssl" / header
    return base.is_file() or base.with_suffix(".h.in").is_file()


def derive_includes(source: Optional[Path]) -> List[str]:
    """Pick public headers implied by the API symbols used in `source`.

    Falls back to the historical BIO/EVP pair when there is no source to look
    at, so existing invocations keep working.
    """
    includes = list(BASE_INCLUDES)
    if source is None or not source.is_file():
        return includes + ["<openssl/bio.h>", "<openssl/evp.h>"]

    text = source.read_text(errors="replace")
    counts = {}
    for match in SYMBOL_SCAN_RE.finditer(text):
        symbol = match.group(0)
        for prefix, header in SYMBOL_HEADERS:
            if symbol.startswith(prefix + "_") and _header_exists(header):
                counts[header] = counts.get(header, 0) + 1
                break

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    for header, _ in ranked[:MAX_DERIVED_INCLUDES]:
        includes.append("<openssl/{}>".format(header))
    if len(includes) == len(BASE_INCLUDES):
        includes.append("<openssl/evp.h>")
    return includes


def _render_includes(includes: Sequence[str]) -> str:
    """Format includes the way in-tree tests do: stdlib group, blank, openssl."""
    stdlib = [h for h in includes if not h.startswith("<openssl/")]
    ossl = [h for h in includes if h.startswith("<openssl/")]
    groups = [g for g in (stdlib, ossl) if g]
    return "\n\n".join(
        "\n".join("#include {}".format(h) for h in group) for group in groups
    )


def generate_stub(prog: str, func: str, source: Optional[Path] = None) -> str:
    """Return a compilable OpenSSL test skeleton for test function `func`."""
    if not TEST_FN_RE.match(func):
        raise StubError("test_fn_name should look like test_foo ({})".format(func))
    includes = derive_includes(source)
    return STUB_TEMPLATE % {
        "year": datetime.date.today().year,
        "prog": prog,
        "func": func,
        "begin": BEGIN_MARKER,
        "end": END_MARKER,
        "includes": _render_includes(includes),
    }


# In snippet mode the model is asked for a function *body*, but it sometimes
# returns the whole function -- signature, braces and all. Spliced between the
# markers that nests a definition inside the stub's own function and never
# compiles; it was 37 identical failures in the first corpus. Unwrapping one
# such layer recovers the run, but the defect must stay countable, so the
# splice reports whether the guard fired rather than silently absorbing it.
FUNC_SIG_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|extern\s+)*"        # storage class, optional
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*"   # return type
    r"[\s*]+"                                        # pointer stars / space
    r"([A-Za-z_][A-Za-z0-9_]*)\s*"                   # the function name
    r"\([^;]*\)\s*\{?\s*$"                           # parameter list
)


def mask_c(text: str) -> str:
    """Return `text` with comments and literals blanked out, length preserved.

    Brace counting has to ignore a '{' inside a string or a comment, and test
    bodies are full of both.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
        elif ch in "\"'":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    out[i] = " "
                    i += 1
                if i < n:
                    if text[i] != "\n":
                        out[i] = " "
                    i += 1
            if i < n:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _significant(lines: Sequence[str]) -> List[int]:
    """Indices of lines that are neither blank nor a whole-line // comment."""
    return [
        i for i, line in enumerate(lines)
        if line.strip() and not line.strip().startswith("//")
    ]


def unwrap_function(body: str) -> Tuple[str, bool]:
    """Strip one enclosing function definition, if that is all `body` is.

    Returns (body, fired). The wrapper is only removed when the opening brace
    that follows the signature stays open until the very last line: that is
    what distinguishes one wrapped function from a body that legitimately
    begins with a helper definition, where stripping would corrupt the code.
    """
    lines = body.splitlines()
    live = _significant(lines)
    if len(live) < 3:
        return body, False

    first, last = live[0], live[-1]
    match = FUNC_SIG_RE.match(lines[first])
    if not match or lines[last].strip() != "}":
        return body, False

    # The opening brace is either on the signature line or alone on the next.
    open_at = first
    if not lines[first].rstrip().endswith("{"):
        nxt = live[1]
        if lines[nxt].strip() != "{":
            return body, False
        open_at = nxt

    masked = mask_c("\n".join(lines)).splitlines()
    depth = 0
    for idx in range(open_at, last + 1):
        depth += masked[idx].count("{") - masked[idx].count("}")
        # Back to top level before the end means this was not a single wrapper.
        if depth <= 0 and idx < last:
            return body, False
    if depth != 0:
        return body, False

    return "\n".join(lines[open_at + 1:last]), True


def sanitize_body(body: str, report: Optional[Dict[str, bool]] = None) -> str:
    """Strip the artifacts models and terminals add around generated code.

    Removes ANSI escapes, CRs, markdown fences, and any replace markers the
    model helpfully echoed back at us, then unwraps a whole function returned
    where a body was asked for. Anything recorded in `report` is what the run
    should carry forward, so a repaired defect stays visible in the results.
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

    body, unwrapped = unwrap_function("\n".join(kept))
    if report is not None:
        report["unwrapped_function"] = unwrapped
    return body


def fill_stub(stub_path: Path, body: str) -> Dict[str, bool]:
    """Replace everything between the markers in `stub_path` with `body`.

    Returns what the splice had to repair, for the run record.
    """
    if not stub_path.is_file():
        raise StubError("stub not found: {}".format(stub_path))

    text = stub_path.read_text()
    if "BEGIN_LLM_REPLACE" not in text:
        raise StubError("missing BEGIN_LLM_REPLACE in {}".format(stub_path))
    if "END_LLM_REPLACE" not in text:
        raise StubError("missing END_LLM_REPLACE in {}".format(stub_path))

    report: Dict[str, bool] = {}
    clean = sanitize_body(body, report)

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
    return report


def read_body(source: str) -> str:
    """Read a generated body from a file path, or from stdin for '-'."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise StubError("body file not found: {}".format(path))
    return path.read_text(errors="replace")
