# syntax=docker/dockerfile:1.7
#
# The self-host gateway: Caddy serving the web app and routing every API on
# one origin (selfhost/gateway/Caddyfile). Built from the repository root.
#
# The bundle is a development-mode build pointed at the `same-origin`
# sentinel, like the headless local stack's (see
# tooling/xtask/crates/xtask_local/src/local/frontend.rs): it calls each API
# relative to wherever it is served, so one image works on any domain. Hosted
# builds hardcode macro.com.

FROM rust:1.94.0-bookworm AS web
ENV RUSTUP_TOOLCHAIN=1.94.0 \
    CARGO_INCREMENTAL=0
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm jq \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add wasm32-unknown-unknown
# CARGO_BUILD_JOBS caps rustc jobs per cargo process. `build-wasm` runs its
# nine packages at once, so the default is a quarter of the cores each.
ARG CARGO_BUILD_JOBS=
RUN --mount=type=cache,id=macro-selfhost-cargo-registry,target=/usr/local/cargo/registry \
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}" \
    && nice -n 10 cargo install --locked just wasm-pack
COPY --from=oven/bun:1 /usr/local/bin/bun /usr/local/bin/bun
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile
WORKDIR /app/apps/web
RUN --mount=type=cache,id=macro-selfhost-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=macro-selfhost-wasm-target,target=/app/target \
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(( ($(nproc) + 3) / 4 ))}" \
    && nice -n 10 just build-wasm
RUN MODE=development NODE_ENV=production NODE_OPTIONS=--max-old-space-size=8192 \
    VITE_LOCAL_SERVERS=ALL \
    VITE_LOCAL_BACKEND_ORIGIN=same-origin \
    VITE_AI_EDITING_WORKER_URL=/ai-editing \
    VITE_SELF_HOSTED=true \
    nice -n 10 bun run --bun build \
    && bun scripts/cache-wasm/cli.ts package-dist --dist dist

FROM caddy:2-alpine
COPY --from=web /app/apps/web/dist /srv/frontend
COPY selfhost/gateway/Caddyfile /etc/caddy/Caddyfile
COPY selfhost/gateway/tls.Caddyfile /etc/caddy/tls.Caddyfile
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    && MACRO_DOMAIN=example.com caddy validate --config /etc/caddy/tls.Caddyfile --adapter caddyfile
