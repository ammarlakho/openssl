#!/bin/bash

IMAGE=mull-openssl
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$CURRENT_DIR/../.." && pwd)"
SCRIPTS_DIR="$REPO_ROOT/thesis-work/scripts"
MULL_CONFIG_PATH="/openssl/thesis-work/mull-mutation/mull.yml"

docker_run() {
    docker run --rm \
        -e "MULL_CONFIG=$MULL_CONFIG_PATH" \
        -v "$REPO_ROOT:/openssl" -w /openssl \
        "$IMAGE" "$@"
}

log_timing() {
    local start=$1
    local operation=$2
    local end=$(date +%s%N)
    local elapsed=$(( (end - start) / 1000000 ))
    local seconds=$(( elapsed / 1000 ))
    local millis=$(( elapsed % 1000 ))
    printf ">> [Timing] %s completed in %d.%03ds\n" "$operation" $seconds $millis
}

build() {
    docker build -t "$IMAGE" "$CURRENT_DIR"
}

make_clean() {
    docker_run bash -c 'make clean 2>/dev/null; true'
}

# Compile for running tests (without coverage)
compile() {
    local start=$(date +%s%N)
    make_clean
    docker_run ./config -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -Xclang -mull-config -Xclang "$MULL_CONFIG_PATH" \
        -g -grecord-command-line
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    docker_run bash -c 'make -s ./test/bio_enc_test -j"$(nproc)"'
    log_timing "$start" "compile"
}

# Reconfigure the tree for coverage-guided mutation. Independent of any one
# test, so a batch of tests only needs this once.
configure-cov() {
    local start=$(date +%s%N)
    make_clean
    docker_run ./config no-shared -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -g -grecord-command-line \
        -fprofile-instr-generate -fcoverage-mapping # only mutate code that is executed by the run of the test/s
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    log_timing "$start" "configure-cov"
}

# Build one test binary in an already-configured tree.
build-test() {
    local start=$(date +%s%N)
    local test="${1:-./test/bio_enc_test}"
    echo "Building test binary: $test"
    docker_run bash -c "make -s $test -j\"\$(nproc)\""
    log_timing "$start" "build-test"
}

# Compile for running mutation tests (with coverage)
compile-cov() {
    local start=$(date +%s%N)
    configure-cov
    build-test "${1:-./test/bio_enc_test}"
    log_timing "$start" "compile-cov"
}

# Run mull and write a machine-readable report next to a human-readable one.
#
#   thesis-work/experiments/results/<name>/<name>.json   Mutation Testing Elements schema
#   thesis-work/experiments/results/<name>/<name>.txt    the usual file:line:col warnings
#
# Override the destination with MULL_REPORT_DIR / MULL_REPORT_NAME.
# Surviving mutants are data here, not a failure, so the exit code is left to
# mean "mull itself could not run".
mutate() {
    local start=$(date +%s%N)
    local test="${1:-./test/bio_enc_test}"
    local name="${MULL_REPORT_NAME:-$(basename "$test")}"
    local report_dir="${MULL_REPORT_DIR:-thesis-work/experiments/results/$name}"
    mkdir -p "$REPO_ROOT/$report_dir"
    echo "Running mutation testing against: $test"
    docker_run mull-runner-18 \
        --reporters IDE --reporters Elements \
        --report-dir "/openssl/$report_dir" --report-name "$name" \
        --allow-surviving --mutation-score-threshold 0 \
        "$test"
    local status=$?
    log_timing "$start" "mutate"
    return $status
}

# Compile for running tests
compile-normal() {
    local start=$(date +%s%N)
    docker_run ./config
    docker_run bash -c 'make -s -j"$(nproc)"'
    log_timing "$start" "compile-normal"
}

# Run ALL tests
test-all() {
    local start=$(date +%s%N)
    docker_run bash -c 'make test'
    log_timing "$start" "test-all"
}

# Run a specific recipe by name, e.g.: ./mull.sh test-recipe test_evp/test_rsa (recipe name without the number- prefix)
test-recipe() {
    local start=$(date +%s%N)
    docker_run bash -c "make test TESTS=$1"
    log_timing "$start" "test-recipe"
}

shell() {
    docker run --rm -it -v "$REPO_ROOT:/openssl" -w /openssl "$IMAGE" bash
}

# ./mull.sh register-test generated_test_cursor
register-test() {
    python3 "$SCRIPTS_DIR/register_test.py" "$@"
}

case "$1" in
    build)       build ;;
    make_clean)  make_clean ;;
    compile)     compile ;;
    compile-cov) compile-cov "$2" ;;
    configure-cov) configure-cov ;;
    build-test)  build-test "$2" ;;
    mutate)      mutate "$2" ;;
    shell)       shell ;;
    run)         compile && mutate "$2" ;;
    run-cov)     compile-cov "$2" && mutate "$2" ;;
    compile-normal) compile-normal ;;
    test-all)    test-all ;;
    test-recipe) test-recipe "$2" ;;
    docker-run) shift; docker_run "$@" ;;
    register-test)    shift; register-test "$@" ;;
    *)
        echo "Usage: ./mull-mutation/mull.sh [build|make_clean|compile|compile-cov|mutate|shell|run|run-cov|add-test] [test]"
        echo ""
        echo "  build        Build toolchain image (Mull + clang; no OpenSSL compile)"
        echo "  make_clean   Run make clean inside the container"
        echo "  compile      Configure + build bio_enc_test — no coverage (~1600 mutants)"
        echo "  compile-cov  Reconfigure + rebuild with coverage + no-shared (default: ./test/bio_enc_test)"
        echo "  configure-cov  Just the coverage reconfigure; share it across many tests"
        echo "  build-test   Build one test binary in an already-configured tree"
        echo "  compile-normal Configure + build without coverage (~1600 mutants)"
        echo "  mutate       Run mutation testing (default: ./test/bio_enc_test)"
        echo "               e.g.: ./mull.sh mutate ./test/generated_test"
        echo "  shell        Interactive shell in the container"
        echo "  run          compile + mutate"
        echo "  run-cov      compile-cov + mutate (optional test arg)"
        echo "  test-all     Run all tests"
        echo "  test-recipe  Run a specific recipe by name, e.g.: ./mull.sh test-recipe test_evp"
        echo "  register-test     Register a new standalone test binary in test/build.info"
        echo "               e.g.: ./mull.sh add-test generated_test_cursor"
        ;;
esac
