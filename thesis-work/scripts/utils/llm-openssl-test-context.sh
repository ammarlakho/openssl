#!/usr/bin/env bash
# Assemble a bundle for LLM test generation / Ollama.
# Uses rg when available; otherwise find + grep.
#
# Prompt order:
#   1) Minimal context banner
#   2) SOURCE_UNDER_TEST — primary (implementation you extend with tests)
#   3) REFERENCE_TESTS — short excerpts from other tests (style/API hints only)
#   4) RULES doc — full contract or snippet rules
#   5) OUTPUT task
#
# Usage (flags before PATH_TO_SOURCE.c):
#   util/llm-openssl-test-context.sh [--snippet] [--impl-lines N] [--refs K] [--lines N]
#       [--full-source] [--task TEXT] [--notes] [--keywords CSV] PATH_TO_SOURCE.c
#   util/llm-openssl-test-context.sh --contract-only [--snippet]
#
# --snippet uses docs/llm-openssl-test-snippet.md instead of full contract and
#           defaults to shorter refs (unless you pass explicit --refs / --lines).
#
# Stub harness (recommended with --snippet):
#   util/gen-openssl-test-stub.sh generated_test test_bio_enc_generated_smoke > test/generated_test.c
#   OLLAMA_MODEL=... util/ollama-openssl-test.sh --into test/generated_test.c --snippet --task "..." crypto/foo.c
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
THESIS_DIR_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTRACT="${THESIS_DIR_ROOT}/docs/llm-openssl-test-contract.md"
SNIPPET_CONTRACT="${THESIS_DIR_ROOT}/docs/llm-openssl-test-snippet.md"

KEYWORDS=""
TOP_K=5
SNIP_LINES=120
IMPL_LINES=280
FULL_SOURCE=0
TASK=""
NOTES=0
CONTRACT_ONLY=0
SNIPPET_MODE=0
LINES_FROM_USER=0
REFS_FROM_USER=0

die() { echo "llm-openssl-test-context: $*" >&2; exit 1; }

[[ -f "${CONTRACT}" ]] || die "missing contract: ${CONTRACT}"
[[ -f "${SNIPPET_CONTRACT}" ]] || die "missing snippet contract: ${SNIPPET_CONTRACT}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keywords) KEYWORDS="$2"; shift 2 ;;
        --refs)
            REFS_FROM_USER=1
            TOP_K="$2"; shift 2 ;;
        --lines)
            LINES_FROM_USER=1
            SNIP_LINES="$2"; shift 2 ;;
        --impl-lines) IMPL_LINES="$2"; shift 2 ;;
        --full-source) FULL_SOURCE=1; shift ;;
        --task) TASK="$2"; shift 2 ;;
        --notes) NOTES=1; shift ;;
        --contract-only) CONTRACT_ONLY=1; shift ;;
        --snippet) SNIPPET_MODE=1; shift ;;
        -h|--help)
            sed -n '1,55p' "$0"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

if [[ "${SNIPPET_MODE}" -eq 1 ]]; then
    [[ "${LINES_FROM_USER}" -eq 0 ]] && SNIP_LINES=50
    [[ "${REFS_FROM_USER}" -eq 0 ]] && TOP_K=4
fi

emit_sep() { printf '\n%s\n\n' "$1"; }

RULES_DOC="${CONTRACT}"
[[ "${SNIPPET_MODE}" -eq 1 ]] && RULES_DOC="${SNIPPET_CONTRACT}"

if [[ "${CONTRACT_ONLY}" -eq 1 ]]; then
    emit_sep "=== RULES (${RULES_DOC}) ==="
    cat "${RULES_DOC}"
    exit 0
fi

[[ $# -eq 1 ]] || die "expected PATH_TO_SOURCE.c (see --help)"
SRC_REL="$1"
if [[ "${SRC_REL}" == /* ]]; then
    SRC="${SRC_REL}"
    case "${SRC}" in
        "${REPO_ROOT}/"*) SRC_REL="${SRC#"${REPO_ROOT}/"}" ;;
    esac
else
    SRC="${REPO_ROOT}/${SRC_REL}"
fi
[[ -f "${SRC}" ]] || die "not a file: ${SRC} (resolved from ${1})"

is_excluded_reference() {
    local b
    b="$(basename "$1")"
    case "${b}" in
        generated_test.c|generated_test_backup.c|generated_test_cursor.c|my_generated.c)
            return 0 ;;
    esac
    return 1
}

emit_sep "=== WHY_YOU_ARE_HERE ==="
printf '%s\n' "Implement or extend automated tests **for behaviors implemented in SOURCE_UNDER_TEST** (${SRC_REL})."
printf '%s\n' "REFERENCE_TESTS are **other tests** copied in short excerpts: style and public API hints only—not a solution scaffold."
[[ "${SNIPPET_MODE}" -eq 1 ]] && printf '%s\n' "**Snippet mode**: assume util/gen-openssl-test-stub.sh (or equivalent) already produced includes and setup_tests; output only replaces BEGIN_LLM_REPLACE ... END_LLM_REPLACE."
[[ -n "${TASK}" ]] && printf '\nScenario: %s\n' "${TASK}"

emit_sep "=== SOURCE_UNDER_TEST (${SRC_REL}) ==="
if [[ "${FULL_SOURCE}" -eq 1 ]]; then
    cat "${SRC}"
else
    head -n "${IMPL_LINES}" "${SRC}"
    wc -l "${SRC}" | awk -v il="${IMPL_LINES}" '{if ($1 > il) print "// ... truncated (total "$1" lines); use --full-source for entire file"}'
fi

STEM="$(basename "${SRC_REL}" .c)"
DIR1="$(basename "$(dirname "${SRC_REL}")")"
DIR2="$(basename "$(dirname "$(dirname "${SRC_REL}")")")"

TMP_LIST="$(mktemp)"
cleanup() { rm -f "${TMP_LIST}"; }
trap cleanup EXIT

HAVE_RG=0
command -v rg >/dev/null 2>&1 && HAVE_RG=1

append_test_matches() {
    local pattern="$1"
    local mode="${2:-glob}"
    [[ -z "${pattern}" ]] && return 0
    if [[ "${HAVE_RG}" -eq 1 ]]; then
        case "${mode}" in
            testonly)
                rg -l --glob '*_test.c' "${pattern}" "${REPO_ROOT}/test" >>"${TMP_LIST}" 2>/dev/null || true
                ;;
            *)
                rg -l --glob '*.c' "${pattern}" "${REPO_ROOT}/test" >>"${TMP_LIST}" 2>/dev/null || true
                ;;
        esac
        return 0
    fi
    local findpat='*.c'
    [[ "${mode}" == testonly ]] && findpat='*_test.c'
    find "${REPO_ROOT}/test" -type f -name "${findpat}" \
        -exec grep -l -- "${pattern}" {} + >>"${TMP_LIST}" 2>/dev/null || true
}

append_test_word_token() {
    local tok="$1"
    local mode="${2:-glob}"
    [[ -z "${tok}" ]] && return 0
    if [[ "${HAVE_RG}" -eq 1 ]]; then
        append_test_matches "\\b${tok}\\b" "${mode}"
        return 0
    fi
    esc_tok="$(printf '%s\n' "${tok}" | sed 's/[][\\.^$*+?{}|()-]/\\&/g')"
    local findpat='*.c'
    [[ "${mode}" == testonly ]] && findpat='*_test.c'
    find "${REPO_ROOT}/test" -type f -name "${findpat}" \
        -exec grep -l -E "[[:<:]]${esc_tok}[[:>:]]" {} + >>"${TMP_LIST}" 2>/dev/null || true
}

if [[ -n "${STEM}" ]]; then
    append_test_word_token "${STEM}" glob
fi
for token in "${DIR1}" "${DIR2}"; do
    [[ "${token}" == "." ]] && continue
    [[ "${#token}" -lt 3 ]] && continue
    append_test_word_token "${token}" testonly
done

while read -r sym; do
    [[ -z "${sym}" ]] && continue
    append_test_matches "${sym}" glob
done < <(grep -oE '\b(BIO_[A-Za-z0-9_]+|EVP_[A-Za-z0-9_]+|SSL_[A-Za-z0-9_]+|RSA_[A-Za-z0-9_]+|EC_[A-Za-z0-9_]+|ASN1_[A-Za-z0-9_]+|X509_[A-Za-z0-9_]+|OSSL_[A-Za-z0-9_]+|CMS_[A-Za-z0-9_]+|PKCS7_[A-Za-z0-9_]+)\b' \
    "${SRC}" 2>/dev/null | sort -u | head -20)

if [[ -n "${KEYWORDS}" ]]; then
    IFS=',' read -ra KW_ARR <<<"${KEYWORDS}"
    for kw in "${KW_ARR[@]}"; do
        kw="$(echo "${kw}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "${kw}" ]] && continue
        append_test_matches "${kw}" glob
    done
fi

REF_FILES="$(
    sort "${TMP_LIST}" 2>/dev/null \
        | uniq -c \
        | sort -k1,1nr -k2,2 \
        | awk '{print $2}' \
        | while read -r f; do
            is_excluded_reference "${f}" && continue
            printf '%s\n' "${f}"
        done \
        | awk '!seen[$0]++' \
        | head -n "${TOP_K}"
)"

emit_sep "=== REFERENCE_TESTS (pattern hints — first ${SNIP_LINES} lines each — not SOURCE_UNDER_TEST) ==="
while IFS= read -r ref; do
    [[ -z "${ref}" ]] && continue
    rel="${ref#"${REPO_ROOT}/"}"
    printf '// --- begin excerpt %s ---\n' "${rel}"
    head -n "${SNIP_LINES}" "${ref}"
    printf '// --- end excerpt %s ---\n\n' "${rel}"
done <<<"${REF_FILES}"

emit_sep "=== RULES (${RULES_DOC}) ==="
cat "${RULES_DOC}"

if [[ "${NOTES}" -eq 1 ]]; then
    emit_sep "=== NOTES (*.md filenames at repo root) ==="
    find "${REPO_ROOT}" -maxdepth 1 -name 'NOTES*.md' -print | sort | sed "s|^${REPO_ROOT}/||"
fi

emit_sep "=== WHAT_TO_EMIT ==="
if [[ "${SNIPPET_MODE}" -eq 1 ]]; then
    printf '%s\n' '- Replace ONLY the code between BEGIN_LLM_REPLACE / END_LLM_REPLACE in your stub (.c scaffold from util/gen-openssl-test-stub.sh).'
    printf '%s\n' '- One cohesive test function body; TEST_* asserts; returns 1 on success, 0 on failure.'
    printf '%s\n' '- No markdown, no narration, no #include/crypto/* fake headers.'
else
    printf '%s\n' "Emit ONE complete compilable unit test module (.c): follow RULES; cover ${SRC_REL} behavior."
    printf '%s\n' 'Output: plain C source only — no markdown fences, no stray escape characters.'
fi
