# Self-hosting Macro

Run Macro on one Docker host with `docker compose`, or as a Docker Compose
application in Coolify and similar platforms.

## How it is laid out

- **One public entrypoint.** `gateway` (Caddy) serves the web app and routes
  every API on one origin. It is the only container with a published port. The
  data stores share an internal network with no route in or out.
- **Feature profiles.** The core runs documents, realtime sync, files,
  notifications and contacts. Optional features run only when you enable
  their profile, so a stack that doesn't need them doesn't pay for them.
- **No secrets to manage.** On first start, `bootstrap` generates every
  secret into the `secrets` volume. Each container loads its own group.
- **Prebuilt images.** These are published to GHCR by
  `.github/workflows/selfhost-images.yml`. You can also build them yourself
  (see *Building the images*).

## Quick start

Everything runs from this directory, `selfhost/`, where `docker-compose.yml`
and its `.env` live:

```sh
cd selfhost
cp .env.example .env
# Edit .env: the Required section at the top (public URL, mail domain, SMTP).
docker compose pull
docker compose up -d
```

The `docker compose` commands below assume you are in `selfhost/`.

Open `MACRO_PUBLIC_URL` and sign in with your email. The login code arrives
through your SMTP relay; there are no passwords.

The first start takes a few minutes while FusionAuth initializes and the
database migrates. `docker compose ps` shows `bootstrap` and `init` as
exited (0) when provisioning is done.

### The first account is the administrator

The stack runs in self-host mode (`MACRO_SELF_HOSTED=true`, and a web app
built with `VITE_SELF_HOSTED=true`):

- **The first account to sign up becomes the root administrator.** On an
  existing install with no administrator, the oldest account is promoted at
  the next start.
- **Signups are invite-only after that.** A new account is accepted when its
  email is on the allowed list or has a pending team invite. The
  administrator changes this, allows emails, promotes other administrators
  and disables accounts under **Settings → Self-host**.
- **Every account has every feature.** There are no plans, trials, billing
  or usage limits, and onboarding can be skipped at any step.
- **Only models you have keys for.** Model pickers list the providers whose
  key is set in `.env` (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GOOGLE_GENERATIVE_AI_API_KEY`, `FIREWORK_API_KEY`, `CEREBRAS_API_KEY`);
  run `docker compose up -d` after changing them (`restart` keeps the old
  values). Voice dictation always needs an OpenAI key.
- **No product analytics.** The web app loads no analytics or ad scripts,
  and the services send nothing to PostHog or Meta.

### HTTPS is required

Session cookies are `Secure`, so browsers only keep them over HTTPS, or on
`http://localhost`. Either:

- Put the gateway behind a proxy that terminates TLS (Coolify, Traefik,
  nginx, Cloudflare Tunnel). Point it at the gateway port (`MACRO_HTTP_PORT`,
  default 8080). Set `MACRO_PUBLIC_URL=https://your.domain`.
- Or enable the `https` profile. It runs Caddy with automatic Let's Encrypt
  certificates on ports 80 and 443. Set `MACRO_DOMAIN=your.domain` and add
  `https` to `COMPOSE_PROFILES`.

To try it on your own machine, `MACRO_PUBLIC_URL=http://localhost:8080` works
without TLS.

## Profiles

Enable profiles with `COMPOSE_PROFILES` in `.env`, comma-separated, or with
`docker compose --profile <name> up -d`.

|Profile|Adds|Needs|
|---|---|---|
|*(core)*|Auth, onboarding, documents, realtime sync, files, notifications, contacts, link previews, agents and AI chat (they answer once model keys are set), OpenSearch (document storage needs it; ~1 GB RAM, and on the host `sysctl vm.max_map_count=262144`)|`MACRO_PUBLIC_URL`, mail settings. For AI: your model provider keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, ...); managed coding sandboxes need `DAYTONA_API_KEY`, and the host Docker socket is never mounted.|
|`search`|Full-text search: indexes content into OpenSearch||
|`ai`|AI document editing worker|Your model provider keys|
|`email`|Gmail inbox and Google Calendar|A Google OAuth client (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET_KEY`)|
|`sso`|Google and GitHub sign-in|`MACRO_AUTH_DOMAIN` and `MACRO_AUTH_PUBLIC_URL`, plus the OAuth clients|
|`whatsapp`|WhatsApp linked devices||
|`slack`|Slack import worker||
|`https`|Automatic TLS on 80/443|`MACRO_DOMAIN`; don't use it under Coolify|
|`mailcatcher`|Mailpit: keeps every outgoing mail in a local inbox at `http://127.0.0.1:8025` instead of delivering it|`SMTP_RELAY_HOST=mailpit`, `SMTP_RELAY_PORT=1025`, `SMTP_RELAY_TLS_LEVEL=may`. For trying the stack only; the relay still refuses recipients whose domain has no mail server|
|`observability`|Grafana with Tempo, Loki and Prometheus (`grafana/otel-lgtm`) at `http://127.0.0.1:3001`, no login|`MACRO_OTEL_GRPC_ENDPOINT=http://otel-lgtm:4317`, `MACRO_OTEL_HTTP_ENDPOINT=http://otel-lgtm:4318`. Without them nothing is exported|

When a feature is off, its API routes answer `503`.

## Coolify

1. Create a resource from this Git repository with the **Docker Compose**
   build pack. Set **Base Directory** to `/selfhost` and **Docker Compose
   Location** to `/docker-compose.yml`.
2. Under **Environment Variables**, set the **Required** section of
   `.env.example` (`MACRO_PUBLIC_URL`, `MACRO_MAIL_DOMAIN` and the SMTP relay),
   plus whatever else you need from it. Coolify asks for the required ones
   before deploying.
3. Set `MACRO_HTTP_BIND=127.0.0.1` so the gateway port is not exposed
   directly. Then assign your domain to the **gateway** service on port
   **80**, for example `https://macro.example.com:80`.
4. Enable features with `COMPOSE_PROFILES`. If your Coolify version ignores
   it, use a custom start command instead:
   `docker compose --profile search --profile ai up -d`.

Leave the `https` profile off; Coolify's proxy handles TLS.

## SSO

FusionAuth builds the Google and GitHub flows on its own hostname. Point a
second DNS name at the gateway (and at your TLS proxy), then set:

```sh
MACRO_AUTH_DOMAIN=auth.macro.example.com
MACRO_AUTH_PUBLIC_URL=https://auth.macro.example.com
COMPOSE_PROFILES=sso
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET_KEY=GOCSPX-...
```

Register `https://auth.macro.example.com/oauth2/callback` as the redirect URI
in Google Cloud Console. On that hostname, the gateway publishes only
FusionAuth's OAuth pages. Its admin UI and API stay private.

## Operations

**Secrets** live in the `macro-selfhost_secrets` volume. They are generated
once and reused on every start. Read one, for example the FusionAuth admin
password:

```sh
docker compose run --rm --no-deps --entrypoint cat bootstrap \
  /run/macro-secrets/fusionauth/FUSIONAUTH_ADMIN_PASSWORD
```

The FusionAuth admin UI is not published. To use it, temporarily publish it on
loopback with a `docker-compose.override.yml` (`ports: ["127.0.0.1:9011:9011"]`
on `fusionauth`).

To use a real value for a generated integration secret, set it on the
service in a `docker-compose.override.yml`. Examples are the Stripe or GitHub
webhook secrets in `tooling/xtask/crates/xtask_local/src/local/selfhost.rs`.
Explicit values win over generated ones.

**Back up these volumes together:** `secrets`, `postgres_data`, `floci_data`
(uploaded files and the KMS keys that encrypt stored integration
credentials), `fusionauth_db_data` and `sync_state` (documents' realtime
state). Stop the stack first, or snapshot the volumes atomically.

**Upgrade** with `docker compose pull && docker compose up -d`. `init` applies
new migrations, queues and topics on every start.

**Requests** are logged by the gateway, one JSON line each:
`docker compose logs -f gateway` shows the path, status and duration of every
call, including routes whose feature is off (`503`). Request headers are not
logged; query strings and the tokens in join, invite, verification, login-code
and webhook paths are replaced, and client addresses masked. Other paths,
document ids and object keys among them, appear as requested. Set
`MACRO_GATEWAY_ACCESS_LOG=discard` to turn it off.

## Building the images

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d
```

Only images of active profiles are built. Set `COMPOSE_PROFILES` before
building `search` or `ai`. The Rust and web builds need about 16 GB of RAM
and 40 GB of disk; they run at low CPU priority, and `CARGO_BUILD_JOBS=4`
caps their parallelism on a host doing other work. To publish to your own
registry, set `MACRO_IMAGE_PREFIX` and run `docker compose ... push`. In a
fork, pushes to `main` publish the images compose pulls by default (`main`);
run the **Self-host images** workflow by hand on any other branch to publish
that branch's images under its name, then set `MACRO_VERSION` to it. A
manual run builds the groups listed in its `images` input (`rust`, `gateway`,
`workers`; all by default), so a web-only change can skip the Rust build.

## Known limits

- **Object storage is Floci**, an S3/SQS/DynamoDB/KMS emulator. It does not
  check request signatures, so the gateway exposes only reads and presigned
  writes of objects in known buckets under `/local-storage`. Object URLs are
  unguessable but not authenticated.
- **Realtime sync** runs the Cloudflare worker under `wrangler dev` (workerd
  and Miniflare). Its state lives in `sync_state`; snapshots also go to
  document storage.
- **Single host.** One instance of every service, with no high availability.
- **Not included:** PDF parsing in search, push notifications to mobile apps,
  the telemetry proxy, and features that depend on Macro's hosted accounts.

## Keeping a fork current

The fork's `upstream` branch mirrors Macro's `main`; the fork's own `main`
carries the self-host stack on top of it, and work branches merge into
`main`. Merge rather than rebase once `main` is published, so its history
never changes under deployments:

```sh
git fetch upstream
git switch upstream && git merge --ff-only upstream/main && git push origin upstream
git switch main && git merge upstream
cargo test -p xtask_local --features selfhost selfhost
```

The self-host tests fail when upstream adds an env var, bucket or route the
stack is missing, and name what to add.
