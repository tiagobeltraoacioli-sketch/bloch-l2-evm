# Pinned build environment for the sparse settlement guests (finding I2 of the
# sparse review: the ELF depended on the build host). Every input that reaches
# the ELF is fixed here or by the commit:
#
#   base image   rust:1.94.1-slim-bookworm, linux/amd64 manifest, by digest
#                (host rustc 1.94.1 for build scripts and proc macros, gcc)
#   SP1 CLI      cargo-prove v6.8.0, release tarball, SHA-256 below
#   guest rustc  succinct-1.96.0-64bit-v2, release tarball, SHA-256 below
#   sources      `git archive` of one commit at the fixed path /bloch-l2-evm
#   registry     CARGO_HOME at the fixed path /cargo, Cargo.lock --locked
#
# The two tarballs are downloaded and checked by build-container.sh on the host
# and copied in; this file fetches nothing, and runs no package manager.
# Digests are those of the GitHub release API for the assets, checked again here.
FROM rust:1.94.1-slim-bookworm@sha256:f845b308e3104231c98dba2dab952ebd54e35cd6ab8ef4a230ecb38e2315f20c

COPY cargo_prove_v6.8.0_linux_amd64.tar.gz rust-toolchain-x86_64-unknown-linux-gnu.tar.gz /tmp/
RUN set -eu; \
    cd /tmp; \
    echo "6b25f9fb1e04009d264b17b7d4bd770bffa900cc004cab7fd4d44a675cf70c42  cargo_prove_v6.8.0_linux_amd64.tar.gz" | sha256sum -c -; \
    echo "ff3afc3a6f22af93d162652972f254fcecf443ca4b2de18897312f19997fb94b  rust-toolchain-x86_64-unknown-linux-gnu.tar.gz" | sha256sum -c -; \
    tar -xzf cargo_prove_v6.8.0_linux_amd64.tar.gz -C /usr/local/bin cargo-prove; \
    mkdir -p /opt/succinct; \
    tar -xzf rust-toolchain-x86_64-unknown-linux-gnu.tar.gz -C /opt/succinct; \
    rm -f /tmp/*.tar.gz; \
    chmod -R a+rX /opt/succinct /usr/local/rustup; \
    rustup toolchain link succinct /opt/succinct; \
    chmod -R a+rX /usr/local/rustup; \
    cargo prove --version; \
    rustc +succinct -vV

ENV CARGO_HOME=/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CARGO_BUILD_JOBS=6 \
    SOURCE_DATE_EPOCH=0 \
    TZ=UTC \
    LC_ALL=C.UTF-8
WORKDIR /bloch-l2-evm/integrations/sp1-execution/guest-sparse
