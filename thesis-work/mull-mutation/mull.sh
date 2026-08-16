#!/bin/bash

IMAGE=mull-openssl
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MULL_CONFIG_PATH="/openssl/thesis-work/mull-mutation/mull.yml"

docker_run() {
    docker run --rm \
        -e "MULL_CONFIG=$MULL_CONFIG_PATH" \
        -v "$REPO_ROOT:/openssl" -w /openssl \
        "$IMAGE" "$@"
}

build() {
    docker build -t "$IMAGE" "$SCRIPT_DIR"
}

make_clean() {
    docker_run bash -c 'make clean 2>/dev/null; true'
}

# Compile for running tests (without coverage)
compile() {
    make_clean
    docker_run ./config -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -Xclang -mull-config -Xclang "$MULL_CONFIG_PATH" \
        -g -grecord-command-line
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    docker_run bash -c 'make -s ./test/bio_enc_test -j"$(nproc)"'
}

# Compile for running mutation tests (with coverage)
compile-cov() {
    local test="${1:-./test/bio_enc_test}"
    make_clean
    docker_run ./config no-shared -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -Xclang -mull-config -Xclang "$MULL_CONFIG_PATH" \
        -g -grecord-command-line \
        -fprofile-instr-generate -fcoverage-mapping # only mutate code that is executed by the run of the test/s
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    echo "Building test binary: $test"
    docker_run bash -c "make -s $test -j\"\$(nproc)\""
}

# Compile for running tests
compile-normal() {
    make_clean
    docker_run ./config
    docker_run bash -c 'make -s -j"$(nproc)"'
}

# Run ALL tests
test-all() {
    docker_run bash -c 'make test'
}
# Run a specific recipe by name, e.g.: ./mull.sh test-recipe 30-test_evp
test-recipe() {
    docker_run bash -c "make test TESTS=$1"
}

mutate() {
    local test="${1:-./test/bio_enc_test}"
    echo "Running mutation testing against: $test"
    docker_run mull-runner-18 "$test"
}

shell() {
    docker run --rm -it -v "$REPO_ROOT:/openssl" -w /openssl "$IMAGE" bash
}

case "$1" in
    build)       build ;;
    make_clean)  make_clean ;;
    compile)     compile ;;
    compile-cov) compile-cov "$2" ;;
    mutate)      mutate "$2" ;;
    shell)       shell ;;
    run)         compile && mutate "$2" ;;
    run-cov)     compile-cov "$2" && mutate "$2" ;;
    compile-normal) compile-normal ;;
    test-all)    test-all ;;
    test-recipe) test-recipe "$2" ;;
    docker-run) shift; docker_run "$@" ;;
    *)
        echo "Usage: ./mull-mutation/mull.sh [build|make_clean|compile|compile-cov|mutate|shell|run|run-cov] [test]"
        echo ""
        echo "  build        Build toolchain image (Mull + clang; no OpenSSL compile)"
        echo "  make_clean   Run make clean inside the container"
        echo "  compile      Configure + build bio_enc_test — no coverage (~1600 mutants)"
        echo "  compile-cov  Reconfigure + rebuild with coverage + no-shared (default: ./test/bio_enc_test)"
        echo "  compile-normal Configure + build without coverage (~1600 mutants)"
        echo "  mutate       Run mutation testing (default: ./test/bio_enc_test)"
        echo "               e.g.: ./mull.sh mutate ./test/generated_test"
        echo "  shell        Interactive shell in the container"
        echo "  run          compile + mutate"
        echo "  run-cov      compile-cov + mutate (optional test arg)"
        echo "  test-all     Run all tests"
        echo "  test-recipe  Run a specific recipe by name, e.g.: ./mull.sh test-recipe 30-test_evp"
        ;;
esac
