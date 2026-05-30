#!/usr/bin/env bash
# Emit a compilable OpenSSL test skeleton to stdout (includes + setup_tests + ADD_TEST).
# Scaffold with this script, then run ollama-openssl-test.sh --into STUB.c (--snippet) to fill
# only the marked region in place (util/fill-openssl-test-stub.sh).
#
# usage: gen-openssl-test-stub.sh <PROGRAM_BASENAME> <test_fn_name>
#   PROGRAM_BASENAME — e.g. generated_ml_test (comment only)
#   test_fn_name — e.g. test_ml_bio_enc_roundtrip (must be test_* identifier)
#
set -euo pipefail

die() { echo "gen-openssl-test-stub: $*" >&2; exit 1; }

[[ "${#}" -eq 2 ]] || die "usage: $0 <PROGRAM_BASENAME> <test_fn_name>"
PROG="$1"
FUNC="$2"
[[ "${FUNC}" =~ ^test_[A-Za-z0-9_]+$ ]] || die "test_fn_name should look like test_foo (${FUNC})"

YEAR="$(date +%Y)"

cat <<EOF
/*
 * Copyright ${YEAR} The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: ${PROG}.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "testutil.h"

static int ${FUNC}(void)
{
    /* BEGIN_LLM_REPLACE */
    return TEST_true(1);
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(${FUNC});
    return 1;
}
EOF
