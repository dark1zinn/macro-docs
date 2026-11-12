# syntax=docker/dockerfile:1.7
#
# The self-host Rust images, built from the repository root:
#   --target services  every service binary under /app/out (compose picks one)
#   --target init      `xtask_local selfhost-init` plus the OpenSearch helpers
#
# Release builds with each service's default features, never the local-only
# ones: `authentication_service` keeps `rate_limit` and never gets
# `return_passwordless_code`, which would answer login requests with the code.

FROM rust:1.94.0-bookworm AS builder
# Selecting the installed toolchain keeps rustup from re-syncing the channel
# rust-toolchain.toml names (see docker/sync-service.Dockerfile).
ENV RUSTUP_TOOLCHAIN=1.94.0 \
    SQLX_OFFLINE=true \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=0
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
COPY --from=oven/bun:1 /usr/local/bin/bun /usr/local/bin/bun
WORKDIR /app
COPY . .
# code_mode_assets generates its embedded SDK bundle with bun at build time.
RUN bun install --frozen-lockfile \
    && (cd packages/sdk && bun install --frozen-lockfile)
# search_processing_service builds without PDF parsing, whose bundled library
# is amd64-only; the local stack runs it the same way.
#
# CARGO_BUILD_JOBS caps parallel rustc jobs (default: every core), and the
# build runs at a lower CPU priority so a host serving other work stays usable.
ARG CARGO_BUILD_JOBS=
RUN --mount=type=cache,id=macro-selfhost-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=macro-selfhost-cargo-target,target=/app/target \
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}" \
    && nice -n 10 cargo build --release --locked \
        --bin authentication_service \
        --bin connection_gateway_service \
        --bin contacts_service \
        --bin document_storage_service \
        --bin document_upload_finalizer_local_worker \
        --bin email_service \
        --bin pubsub_workers \
        --bin calendar_service \
        --bin notification_service \
        --bin static_file_service \
        --bin unfurl_service \
        --bin image_proxy_service \
        --bin agent_harness_service \
        --bin whatsapp_session_service \
        --bin slack_import_worker \
    && nice -n 10 cargo build --release --locked -p search_processing_service \
        --no-default-features --features processing,service \
        --bin search_processing_service \
    && nice -n 10 cargo build --release --locked -p xtask_local --features selfhost --bin xtask_local \
    && mkdir -p /out \
    && cp target/release/authentication_service \
          target/release/connection_gateway_service \
          target/release/contacts_service \
          target/release/document_storage_service \
          target/release/document_upload_finalizer_local_worker \
          target/release/email_service \
          target/release/pubsub_workers \
          target/release/calendar_service \
          target/release/notification_service \
          target/release/static_file_service \
          target/release/unfurl_service \
          target/release/image_proxy_service \
          target/release/agent_harness_service \
          target/release/whatsapp_session_service \
          target/release/slack_import_worker \
          target/release/search_processing_service \
          /out/ \
    && mkdir -p /init \
    && cp target/release/xtask_local /init/ \
    && strip /out/* /init/*

FROM debian:trixie-slim AS services
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# The agent harness runs routine code under Deno.
COPY --from=denoland/deno:2.9.6 /usr/bin/deno /usr/local/bin/deno
ENV DENO_BINARY=/usr/local/bin/deno \
    PORT=8080
WORKDIR /app
COPY --from=builder /out/ /app/out/
EXPOSE 8080

FROM debian:trixie-slim AS init
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=oven/bun:1 /usr/local/bin/bun /usr/local/bin/bun
COPY infra/stacks/opensearch/helpers /opt/opensearch-helpers
RUN cd /opt/opensearch-helpers && bun install --frozen-lockfile
COPY --from=builder /init/xtask_local /usr/local/bin/xtask_local
