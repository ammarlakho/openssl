#!/usr/bin/env bash
# Pipe OPENSSL_TEST_CONTRACT + retrieval bundle into Ollama.
# Same arguments as scripts/utils/llm-openssl-test-context.sh (see that script).
#
#   OLLAMA_MODEL=qwen2.5-coder:7b ./scripts/ollama-openssl-test.sh crypto/evp/bio_enc.c --task "scenario"
#
# Splice snippet output into an existing stub (no manual paste):
#
#   OLLAMA_MODEL=qwen2.5-coder:7b ./scripts/ollama-openssl-test.sh --into test/generated_test.c \\
#       --snippet --task "..." crypto/evp/bio_enc.c
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="${OLLAMA_MODEL:-qwen2.5-coder:7b}"
INTO=""
SECONDS=0

command -v ollama >/dev/null 2>&1 || {
    echo "ollama-openssl-test: 'ollama' not found in PATH" >&2
    exit 1
}

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --into)
            [[ $# -ge 2 ]] || {
                echo "ollama-openssl-test: --into requires a stub .c path" >&2
                exit 1
            }
            INTO="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -n "${INTO}" ]]; then
    BODY="$(mktemp)"
    trap 'rm -f "${BODY}"' EXIT
    "${SCRIPT_DIR}/utils/llm-openssl-test-context.sh" "${ARGS[@]}" | ollama run "${MODEL}" --keepalive 0 >"${BODY}"
    "${SCRIPT_DIR}/utils/fill-openssl-test-stub.sh" "${INTO}" "${BODY}"
else
    "${SCRIPT_DIR}/utils/llm-openssl-test-context.sh" "${ARGS[@]}" | ollama run "${MODEL}" --keepalive 0
fi

echo "ollama-openssl-test completed in ${SECONDS}s" >&2
