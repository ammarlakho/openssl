"""Scaffold a test .c skeleton and splice model output into it."""

import datetime
import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

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
