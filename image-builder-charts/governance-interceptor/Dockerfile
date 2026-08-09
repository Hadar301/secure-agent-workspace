FROM --platform=linux/amd64 rust:1.90-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev git make cmake g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 https://github.com/NVIDIA/OpenShell.git .

WORKDIR /build/examples/governance-interceptor
RUN cargo build --release && ls -la /build/target/release/openshell*

FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openshell-governance-interceptor-example /usr/local/bin/governance-interceptor
ENTRYPOINT ["governance-interceptor"]
