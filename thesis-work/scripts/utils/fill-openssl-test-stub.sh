#!/usr/bin/env bash
# Replace the body between BEGIN_LLM_REPLACE / END_LLM_REPLACE in a stub .c file.
# Sanitizes common LLM / Ollama artifacts before splicing (markers, fences, ANSI escapes).
#
# usage: fill-openssl-test-stub.sh STUB.c [BODY_FILE]
#   BODY_FILE defaults to stdin
#
set -euo pipefail

die() { echo "fill-openssl-test-stub: $*" >&2; exit 1; }

[[ "${#}" -ge 1 && "${#}" -le 2 ]] || die "usage: $0 STUB.c [BODY_FILE]"
STUB="$1"
BODY="${2:--}"

[[ -f "${STUB}" ]] || die "stub not found: ${STUB}"
grep -q 'BEGIN_LLM_REPLACE' "${STUB}" || die "missing BEGIN_LLM_REPLACE in ${STUB}"
grep -q 'END_LLM_REPLACE' "${STUB}" || die "missing END_LLM_REPLACE in ${STUB}"

TMP_BODY="$(mktemp)"
TMP_CLEAN="$(mktemp)"
TMP_OUT="$(mktemp)"
trap 'rm -f "${TMP_BODY}" "${TMP_CLEAN}" "${TMP_OUT}"' EXIT

if [[ "${BODY}" == "-" ]]; then
    cat >"${TMP_BODY}"
else
    [[ -f "${BODY}" ]] || die "body file not found: ${BODY}"
    cp "${BODY}" "${TMP_BODY}"
fi

sanitize_llm_body() {
    # Strip CSI/OSC ANSI escapes (Ollama spinner, terminal cursor moves, etc.).
    sed $'s/\x1b\\][^\x07]*\x07//g' \
        | sed $'s/\x1b\\][^\x1b\\]*(\x07|\x1b\\\\)//g' \
        | sed $'s/\x1b\\[[0-9;?]*[ -\/]*[@-~]//g' \
        | tr -d '\r' \
        | awk '
            function trim(s) {
                sub(/^[ \t\r\n]+/, "", s)
                sub(/[ \t\r\n]+$/, "", s)
                return s
            }
            function is_marker(s) {
                s = trim(s)
                if (s == "BEGIN_LLM_REPLACE" || s == "END_LLM_REPLACE")
                    return 1
                if (s ~ /^\/\*[ \t]*BEGIN_LLM_REPLACE[ \t]*\*\/$/)
                    return 1
                if (s ~ /^\/\*[ \t]*END_LLM_REPLACE[ \t]*\*\/$/)
                    return 1
                return 0
            }
            function is_fence(s) {
                s = trim(s)
                return s ~ /^```/
            }
            {
                line = $0
                if (is_marker(line) || is_fence(line))
                    next
                print
            }
        '
}

sanitize_llm_body <"${TMP_BODY}" >"${TMP_CLEAN}"

awk -v bodyfile="${TMP_CLEAN}" '
    /\/\* BEGIN_LLM_REPLACE \*\// {
        print
        while ((getline line < bodyfile) > 0)
            print line
        close(bodyfile)
        skip = 1
        next
    }
    skip {
        if (/\/\* END_LLM_REPLACE \*\//) {
            skip = 0
            print
        }
        next
    }
    { print }
' "${STUB}" >"${TMP_OUT}"

mv "${TMP_OUT}" "${STUB}"
