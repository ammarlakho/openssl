#!/bin/bash

IMAGE=mull-openssl
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MULL_CONFIG_PATH="/openssl/mull-mutation/mull.yml"

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

compile() {
    make_clean
    docker_run ./config -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -g -grecord-command-line
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    docker_run bash -c 'make -s ./test/bio_enc_test -j"$(nproc)"'
}

compile-cov() {
    make_clean
    docker_run ./config no-shared -O0 \
        -fpass-plugin=/usr/lib/mull-ir-frontend-18 \
        -g -grecord-command-line \
        -fprofile-instr-generate -fcoverage-mapping
    docker_run bash -c 'make -s build_generated -j"$(nproc)"'
    docker_run bash -c 'make -s ./test/bio_enc_test -j"$(nproc)"'
}

mutate() {
    docker_run mull-runner-18 ./test/bio_enc_test
}

shell() {
    docker run --rm -it -v "$REPO_ROOT:/openssl" -w /openssl "$IMAGE" bash
}

case "$1" in
    build)       build ;;
    make_clean)  make_clean ;;
    compile)     compile ;;
    compile-cov) compile-cov ;;
    mutate)      mutate ;;
    shell)       shell ;;
    run)         compile && mutate ;;
    run-cov)     compile-cov && mutate ;;
    *)
        echo "Usage: ./mull-mutation/mull.sh [build|make_clean|compile|compile-cov|mutate|shell|run|run-cov]"
        echo ""
        echo "  build        Build toolchain image (Mull + clang; no OpenSSL compile)"
        echo "  make_clean   Run make clean inside the container"
        echo "  compile      Configure + build bio_enc_test — no coverage (~1600 mutants)"
        echo "  compile-cov  Reconfigure + rebuild with coverage + no-shared (~40 mutants in real crypto code)"
        echo "  mutate       Run mutation testing against ./test/bio_enc_test"
        echo "  shell        Interactive shell in the container"
        echo "  run          compile + mutate"
        echo "  run-cov      compile-cov + mutate"
        ;;
esac
