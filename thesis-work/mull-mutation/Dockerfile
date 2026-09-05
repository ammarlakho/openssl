FROM ubuntu:24.04

# Toolchain only — OpenSSL is compiled via `./mull-mutation/mull.sh compile` with a bind mount
# so incremental `make` works and you rarely rebuild this image.

RUN apt-get update && apt-get install -y \
    curl \
    clang-18 \
    make \
    perl \
    && curl -1sLf 'https://dl.cloudsmith.io/public/mull-project/mull-stable/setup.deb.sh' | bash \
    && apt-get update && apt-get install -y mull-18 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /openssl

ENV CC=clang-18
