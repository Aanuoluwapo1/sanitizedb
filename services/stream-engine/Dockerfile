FROM rust:1-slim-bookworm AS builder
WORKDIR /workspace

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY packages/proto ./packages/proto
COPY services/stream-engine ./services/stream-engine

WORKDIR /workspace/services/stream-engine
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 sanitizedb
USER 10001
COPY --from=builder /workspace/services/stream-engine/target/release/stream-engine /usr/local/bin/stream-engine
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/stream-engine"]
