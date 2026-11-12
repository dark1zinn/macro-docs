# selfhost

## What it is

The self-host deployment: `docker-compose.yml` at the repository root runs
Macro on one Docker host behind a single public gateway, with optional
features as compose profiles. This directory holds its images, gateway config,
env template and operator guide.

## How it works

`bootstrap` generates secrets into a volume and renders the FusionAuth
kickstart; `init` migrates MacroDB and provisions Floci (S3/SQS/DynamoDB/KMS),
Kafka topics and FusionAuth redirects. Both are `cargo x selfhost-init`
(`tooling/xtask/crates/xtask_local/src/local/selfhost.rs`), built into the
`init` image. Every service starts through the generated `load.sh`, which
exports its secret group. Services run with `ENVIRONMENT=local`; the public
origin comes from `MACRO_PUBLIC_URL`.

Self-host mode (`MACRO_SELF_HOSTED=true` for services, `VITE_SELF_HOSTED=true`
in the web build) entitles every account, makes the first account root admin,
gates new accounts on a DB signup policy and turns off product analytics. The
backend lives in `crates/selfhost`; the web reads `SELF_HOSTED` from
`apps/web/src/lib/core/constant/featureFlags.ts`.

## Start here

- `../docker-compose.yml`: services, profiles, networks, the shared env.
- `gateway/Caddyfile`: every public route.
- `../tooling/xtask/crates/xtask_local/src/local/selfhost.rs`: secrets, kickstart, provisioning.
- `../crates/selfhost`: entitlements, root admin, signup policy, admin API rules.

## Recipes

- The local stack gains an env var: add it to `x-macro-env` (the drift test names it).
- New generated secret: a `SECRETS` entry in `selfhost.rs`; never set it in compose.
- New public route: `gateway/Caddyfile`, mirroring `xtask_local/src/local/proxy.rs`.
- New service: a compose service (profiled if optional), its build in
  `../docker-compose.build.yml`, its image in
  `tooling/xtask/crates/xtask_workflows/src/workflows/selfhost_images.rs`.

## Checks

- `cargo test -p xtask_local --features selfhost selfhost`
- `docker compose --env-file selfhost/env.example config --quiet`
- If a workflow changed: `cargo x workflows --check`

## Gotchas

- Never build `authentication_service` with `return_passwordless_code` or
  without `rate_limit`: the first returns login codes in the response.
- `Production`/`Develop` hardcode macro.com hosts; self-host must stay `local`.
- A secret set in compose `environment` silently wins over the generated one.
- Coolify applies every `${VAR:?}` regardless of profile: only core settings may be required.
- Floci accepts unsigned requests; the gateway's `/local-storage` allowlist is the only guard.
- This is a fork that merges upstream: keep self-host logic in new files and
  only short hooks in upstream code (`authentication_service` login/webhook
  handlers, `server.rs`, the web flag sites).
- Leave `POSTHOG_API_KEY` out of `x-macro-env`: a set key turns analytics on.

## Related

- Docs: `README.md` (operators) · `docs/development/running-locally.md` (the local stack it derives from)
