# OpenShell 0.1.x needs Rust 1.94 (rust-version in its Cargo.toml).
FROM --platform=linux/amd64 rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev git make cmake g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ARG OPENSHELL_REF=main
RUN git init . \
    && git remote add origin https://github.com/NVIDIA/OpenShell.git \
    && git fetch --depth 1 origin "${OPENSHELL_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /build/examples/governance-interceptor
# Workaround for NVIDIA/OpenShell#3929 (v0.1.2): the gateway hashes provider
# profile annotations in map order, so a profile with more than one annotation
# gives a different provider_env_revision on every call and no sandbox with a
# provider becomes ready ("Startup configuration did not stabilize"). Keep only
# the signature JWT, which already carries the hash (claim) and key id (header);
# the gateway treats the annotations as opaque. Drop this once #3929 is fixed.
RUN perl -0pi -e 's/\n    profile\n        \.annotations\n        \.insert\(PROFILE_HASH_ANNOTATION\.to_string\(\), profile_hash\);\n    profile\.annotations\.insert\(\n        PROFILE_SIGNATURE_KID_ANNOTATION\.to_string\(\),\n        policy_signer\.kid\(\)\.to_string\(\),\n    \);\n/\n/' src/main.rs \
    && ! grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs
RUN cargo build --release --target-dir /out

FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/release/governance-interceptor /usr/local/bin/governance-interceptor
ENTRYPOINT ["governance-interceptor"]
