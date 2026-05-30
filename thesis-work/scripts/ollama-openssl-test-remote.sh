#!/usr/bin/env bash
# Pipe OPENSSL_TEST_CONTRACT + retrieval bundle into a remote OpenAI-compatible LLM.
#
# Usage:
#   ./scripts/ollama-openssl-test-remote.sh [--profile gptoss|gemma] [--into <stub.c>] [<context-args>]
#
#   Override any value from the env file via environment variables:
#     LLM_PROFILE, API_URL, LLM_MODEL
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THESIS_DIR_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SECONDS=0

# Load env
ENV="${THESIS_DIR_ROOT}/llm-models.env"
[[ -f "${ENV}" ]] && source "${ENV}"

# Check for required tools
command -v curl >/dev/null 2>&1 || { echo "error: 'curl' is required for the API call" >&2; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "error: 'jq' is required for JSON parsing"    >&2; exit 1; }

INTO=""
ARGS=()
PROFILE="${LLM_PROFILE:-gptoss}"

# 1. Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --into)
            [[ $# -ge 2 ]] || { echo "error: --into requires a stub .c path" >&2; exit 1; }
            INTO="$2"
            shift 2
            ;;
        --profile)
            [[ $# -ge 2 ]] || { echo "error: --profile requires a profile name" >&2; exit 1; }
            PROFILE="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Apply default context args when none given (--into only controls output destination)
if [[ ${#ARGS[@]} -eq 0 ]]; then
    echo ">> [Info] No context arguments provided. Applying default AES-256 snippet task..." >&2
    [[ -n "${INTO}" ]] || INTO="test/generated_test.c"
    ARGS=(
        "--snippet"
        "--impl-lines" "400"
        "--task" "AES-256 CBC BIO round-trip vs fixed vectors"
        "crypto/evp/bio_enc.c"
    )
fi

# Note: --profile defaults to gptoss if not specified

# 2. Resolve API_URL and MODEL from environment variables (required)
case "${PROFILE}" in
    gptoss)
        API_URL="${API_URL:-${GPTOSS_API_URL:-}}"
        MODEL="${LLM_MODEL:-${GPTOSS_MODEL:-}}"
        ;;
    gemma)
        API_URL="${API_URL:-${GEMMA_API_URL:-}}"
        MODEL="${LLM_MODEL:-${GEMMA_MODEL:-}}"
        ;;
    *)
        echo "error: unknown profile '${PROFILE}'. Valid options: gptoss, gemma" >&2
        exit 1
        ;;
esac

# Validate that API_URL and MODEL are set
if [[ -z "${API_URL}" ]]; then
    echo "error: API_URL is not set. Set it via API_URL env var or ${PROFILE}_API_URL" >&2
    exit 1
fi
if [[ -z "${MODEL}" ]]; then
    echo "error: MODEL is not set. Set it via LLM_MODEL env var or ${PROFILE}_MODEL" >&2
    exit 1
fi

# 3. Generate the context/prompt text
if [[ ${#ARGS[@]} -gt 0 ]]; then
    PROMPT=$("${SCRIPT_DIR}/utils/llm-openssl-test-context.sh" "${ARGS[@]}")
else
    PROMPT=$("${SCRIPT_DIR}/utils/llm-openssl-test-context.sh")
fi

# 4. Escape the prompt safely so multi-line C code doesn't break the JSON payload
ESCAPED_PROMPT=$(echo "$PROMPT" | jq -Rs .)

# 5. Define a function to call the API, log metadata, and extract just the text response
call_remote_llm() {
    local RAW_RESPONSE

    RAW_RESPONSE=$(curl -sS --location "${API_URL}" \
        --header 'Content-Type: application/json' \
        --data '{
            "model": "'"${MODEL}"'",
            "messages": [
                {
                    "role": "user",
                    "content": '"${ESCAPED_PROMPT}"'
                }
            ]
        }') || {
            echo ">> [Error] Curl command failed. Check your API_URL or network connection." >&2
            exit 1
        }

    local API_ERROR
    API_ERROR=$(echo "$RAW_RESPONSE" | jq -r '.error.message // empty')
    if [[ -n "$API_ERROR" ]]; then
        echo ">> [API Error] ${API_ERROR}" >&2
        echo ">> [Raw Output] ${RAW_RESPONSE}" >&2
        exit 1
    fi

    local RES_MODEL RES_FINGERPRINT
    RES_MODEL=$(echo "$RAW_RESPONSE" | jq -r '.model // "N/A"')
    RES_FINGERPRINT=$(echo "$RAW_RESPONSE" | jq -r '.system_fingerprint // "N/A"')
    echo ">> [API Log] Profile: ${PROFILE} | Model: ${RES_MODEL} | Fingerprint: ${RES_FINGERPRINT}" >&2

    echo "$RAW_RESPONSE" | jq -r '.choices[0].message.content // "Error: no content returned"'
}

# 6. Route the output appropriately based on the --into flag
if [[ -n "${INTO}" ]]; then
    BODY="$(mktemp)"
    trap 'rm -f "${BODY}"' EXIT

    echo ">> [Info] Querying remote LLM (${MODEL}) and writing to ${INTO}..." >&2
    call_remote_llm >"${BODY}"

    "${SCRIPT_DIR}/utils/fill-openssl-test-stub.sh" "${INTO}" "${BODY}"
else
    call_remote_llm
fi

echo ">> [Timing] Remote LLM query completed in ${SECONDS}s" >&2
