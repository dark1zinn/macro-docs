//! `cargo x selfhost-init`: the in-container bootstrap of the self-host
//! compose stack (`docker-compose.yml` at the repository root).
//!
//! It reuses the local stack's single-source catalogs rather than restating
//! them: the AWS resources come from [`resources`](super::resources) through
//! [`localstack`], the topics from `macro_event_topics` through [`kafka`], and
//! the FusionAuth bootstrap from [`kickstart::build`] with its local-only
//! secrets swapped for `#{ENV.*}` references FusionAuth resolves at startup.
//!
//! - `bootstrap` generates the deployment's secrets once into a volume, writes
//!   the loader every container starts through, and the kickstart document.
//! - `provision` migrates MacroDB and creates queues, buckets, tables, KMS
//!   aliases, topics and the FusionAuth redirect URLs. Idempotent.
//! - `search` creates the OpenSearch indices (the `search` profile).
//! - `sso` adds the Google/GitHub identity providers (the `sso` profile).

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};

use super::{identity, kafka, kickstart, localstack};

/// Keeps `docker-compose.yml` and the gateway in step with the local stack.
#[cfg(test)]
mod drift;
#[cfg(test)]
mod test;

/// How long `provision` and `search` wait for each dependency to answer.
const WAIT_LIMIT: Duration = Duration::from_secs(300);
const RETRY_EVERY: Duration = Duration::from_secs(2);

const POPULATE_JWT_LAMBDA: &str = include_str!(
    "../../../../../../infra/stacks/fusionauth-instance/templates/populate_jwt_local.js"
);
const RECONCILE_LAMBDA: &str = include_str!(
    "../../../../../../infra/stacks/fusionauth-instance/templates/reconcile_secondary_idp_link.js"
);

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: SelfhostCmd,
}

#[derive(Subcommand)]
enum SelfhostCmd {
    /// Generate missing secrets, the loader script and the FusionAuth kickstart.
    Bootstrap {
        #[arg(long, default_value = "/run/macro-secrets")]
        secrets_dir: PathBuf,
        #[arg(long, default_value = "/run/macro-kickstart")]
        kickstart_dir: PathBuf,
    },
    /// Migrate MacroDB and provision AWS resources, topics and FusionAuth.
    Provision,
    /// Create the OpenSearch indices.
    Search {
        #[arg(long, default_value = "/opt/opensearch-helpers")]
        helpers_dir: PathBuf,
    },
    /// Create or update the configured Google/GitHub identity providers.
    Sso,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SelfhostCmd::Bootstrap {
            secrets_dir,
            kickstart_dir,
        } => bootstrap(&secrets_dir, &kickstart_dir),
        SelfhostCmd::Provision => provision(),
        SelfhostCmd::Search { helpers_dir } => search(&helpers_dir),
        SelfhostCmd::Sso => sso(),
    }
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// The shape of a generated secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SecretKind {
    /// 32 hex characters.
    Hex32,
    /// 64 hex characters.
    Hex64,
    /// A base64-encoded 32-byte AES key.
    Base64Key32,
    /// A 2048-bit RSA key pair in PEM (PKCS#8 private, SPKI public).
    RsaKeyPair,
}

/// A generated secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SecretValue {
    Single(String),
    Pair { private: String, public: String },
}

/// How a file's contents derive from its secret.
#[derive(Clone, Copy)]
pub(super) enum Template {
    /// The value itself (the private half of a pair).
    Raw,
    /// The public half of a pair.
    Public,
    /// The value substituted for the `{}` in the pattern.
    Fmt(&'static str),
}

/// One file the secret is written to: `<group>/<name>`. The group is the
/// directory a container loads (`load.sh <group>`), the name the env var.
pub(super) struct SecretFile {
    pub group: &'static str,
    pub name: &'static str,
    pub template: Template,
}

/// A generated secret and every env var it is exposed as.
pub(super) struct Secret {
    pub canonical: &'static str,
    pub kind: SecretKind,
    pub files: &'static [SecretFile],
}

const fn raw(group: &'static str, name: &'static str) -> SecretFile {
    SecretFile {
        group,
        name,
        template: Template::Raw,
    }
}

const fn fmt(group: &'static str, name: &'static str, pattern: &'static str) -> SecretFile {
    SecretFile {
        group,
        name,
        template: Template::Fmt(pattern),
    }
}

/// The group every Macro service container loads.
pub(super) const APP: &str = "app";
const FUSIONAUTH: &str = "fusionauth";
const POSTGRES: &str = "postgres";
const FUSIONAUTH_DB: &str = "fusionauth-db";

const MACRO_DB_URL: &str = "postgres://macro:{}@postgres:5432/macrodb";

/// Every secret the deployment generates. Several services read one value
/// under different names (the local stack sets them all to one constant, see
/// `local_env::ServiceAuthEnv`), so each canonical value fans out to aliases.
pub(super) const SECRETS: &[Secret] = &[
    Secret {
        canonical: "POSTGRES_PASSWORD",
        kind: SecretKind::Hex32,
        files: &[
            raw(POSTGRES, "POSTGRES_PASSWORD"),
            fmt(APP, "DATABASE_URL", MACRO_DB_URL),
            fmt(APP, "DATABASE_URL_READONLY", MACRO_DB_URL),
            fmt(APP, "MACRO_DB_URL", MACRO_DB_URL),
        ],
    },
    Secret {
        canonical: "FUSIONAUTH_DB_PASSWORD",
        kind: SecretKind::Hex32,
        files: &[
            raw(FUSIONAUTH_DB, "POSTGRES_PASSWORD"),
            raw(FUSIONAUTH, "DATABASE_PASSWORD"),
            raw(FUSIONAUTH, "DATABASE_ROOT_PASSWORD"),
        ],
    },
    Secret {
        canonical: "FUSIONAUTH_API_KEY",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "FUSIONAUTH_API_KEY"),
            raw(APP, "FUSIONAUTH_API_KEY_SECRET_KEY"),
            raw(FUSIONAUTH, "FUSIONAUTH_API_KEY"),
        ],
    },
    Secret {
        canonical: "JWT_SECRET_KEY",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "JWT_SECRET_KEY"),
            raw(FUSIONAUTH, "JWT_SECRET_KEY"),
        ],
    },
    Secret {
        canonical: "FUSIONAUTH_CLIENT_SECRET",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "FUSIONAUTH_CLIENT_SECRET_KEY"),
            raw(FUSIONAUTH, "FUSIONAUTH_CLIENT_SECRET_KEY"),
        ],
    },
    Secret {
        canonical: "FUSIONAUTH_ADMIN_PASSWORD",
        kind: SecretKind::Hex32,
        files: &[raw(FUSIONAUTH, "FUSIONAUTH_ADMIN_PASSWORD")],
    },
    Secret {
        canonical: "INTERNAL_API_SECRET_KEY",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "INTERNAL_API_SECRET_KEY"),
            raw(APP, "INTERNAL_API_KEY"),
            raw(APP, "INTERNAL_AUTH_KEY"),
            raw(APP, "AUTHENTICATION_SERVICE_SECRET_KEY"),
            raw(APP, "SYNC_SERVICE_AUTH_KEY"),
            raw(APP, "SERVICE_INTERNAL_AUTH_KEY"),
            raw(APP, "DOCUMENT_STORAGE_SERVICE_AUTH_KEY"),
            raw(APP, "DSS_INTERNAL_AUTH_KEY"),
            raw(APP, "LEXICAL_SERVICE_AUTH_KEY"),
            raw(FUSIONAUTH, "INTERNAL_API_SECRET_KEY"),
        ],
    },
    Secret {
        canonical: "DOCUMENT_PERMISSION_JWT",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "DOCUMENT_PERMISSION_JWT"),
            raw(APP, "DOCUMENT_PERMISSIONS_SECRET"),
        ],
    },
    Secret {
        canonical: "INTERNAL_CALL_SECRET",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "INTERNAL_CALL_SECRET")],
    },
    Secret {
        canonical: "URL_SIGNING_HMAC",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "URL_SIGNING_HMAC")],
    },
    Secret {
        canonical: "ACCOUNT_LINK_STATE_SECRET",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "ACCOUNT_LINK_STATE_SECRET")],
    },
    Secret {
        canonical: "MCP_CREDENTIALS_KEY_SECRET_NAME",
        kind: SecretKind::Base64Key32,
        files: &[raw(APP, "MCP_CREDENTIALS_KEY_SECRET_NAME")],
    },
    // Webhook and OAuth-state verification keys. The local stack's stubs are
    // public strings, which would let anyone forge these callbacks here.
    Secret {
        canonical: "PIPEDREAM_WEBHOOK_SECRET",
        kind: SecretKind::Hex64,
        files: &[
            raw(APP, "PIPEDREAM_WEBHOOK_SECRET"),
            fmt(
                APP,
                "PIPEDREAM_WEBHOOK_URI",
                "http://localhost:8080/pipedream/mcp/webhook?secret={}",
            ),
        ],
    },
    Secret {
        canonical: "GITHUB_INSTALLATION_STATE_SECRET",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "GITHUB_INSTALLATION_STATE_SECRET")],
    },
    Secret {
        canonical: "GITHUB_WEBHOOK_SECRET_KEY",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "GITHUB_WEBHOOK_SECRET_KEY")],
    },
    Secret {
        canonical: "STRIPE_WEBHOOK_SECRET_KEY",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "STRIPE_WEBHOOK_SECRET_KEY")],
    },
    Secret {
        canonical: "CAL_WEBHOOK_SECRET_KEY",
        kind: SecretKind::Hex64,
        files: &[raw(APP, "CAL_WEBHOOK_SECRET_KEY")],
    },
    Secret {
        canonical: "MACRO_API_TOKEN",
        kind: SecretKind::RsaKeyPair,
        files: &[
            raw(APP, "MACRO_API_TOKEN_PRIVATE_SECRET_KEY"),
            SecretFile {
                group: APP,
                name: "MACRO_API_TOKEN_PUBLIC_KEY",
                template: Template::Public,
            },
        ],
    },
];

/// Exports every file of a group as an env var, unless the var is already set,
/// then execs the container's command. Every container starts through it.
pub(super) const LOADER_SH: &str = r#"#!/bin/sh
set -eu
dir="${MACRO_SECRETS_DIR:-/run/macro-secrets}/$1"; shift
for f in "$dir"/*; do
  [ -f "$f" ] || continue
  name=${f##*/}
  eval "current=\${$name:-}"
  [ -n "$current" ] || export "$name=$(cat "$f")"
done
exec "$@"
"#;

/// Groups loaded by containers that do not run as root, and their uid. The
/// FusionAuth image runs as `fusionauth` (1001).
const CONTAINER_USERS: &[(&str, u32)] = &[(FUSIONAUTH, 1001)];

/// Write every secret's files under `dir`, generating a canonical value only
/// when none is stored yet, plus the loader. Re-running regenerates nothing:
/// it rewrites the files from the stored values, so an alias added in a later
/// release receives the value its siblings already have. Groups listed in
/// `owners` are handed to that uid.
pub(super) fn write_secrets(
    dir: &Path,
    owners: &[(&str, u32)],
    generate: &mut dyn FnMut(SecretKind) -> Result<SecretValue>,
) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // Traversable, so a non-root container reaches its own group directory.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let canonical_dir = dir.join(".canonical");
    create_private_dir(&canonical_dir)?;
    for secret in SECRETS {
        let value = load_or_generate(&canonical_dir, secret, generate)?;
        for file in secret.files {
            let contents = match (file.template, &value) {
                (Template::Raw, SecretValue::Single(value)) => value.clone(),
                (Template::Raw, SecretValue::Pair { private, .. }) => private.clone(),
                (Template::Public, SecretValue::Pair { public, .. }) => public.clone(),
                (Template::Fmt(pattern), SecretValue::Single(value)) => {
                    pattern.replacen("{}", value, 1)
                }
                _ => bail!(
                    "secret {}: file {}/{} does not fit its kind",
                    secret.canonical,
                    file.group,
                    file.name
                ),
            };
            let group_dir = dir.join(file.group);
            create_private_dir(&group_dir)?;
            let path = group_dir.join(file.name);
            write_file(&path, &contents, 0o600)?;
            if let Some(&(_, uid)) = owners.iter().find(|(group, _)| *group == file.group) {
                std::os::unix::fs::chown(&group_dir, Some(uid), Some(uid))
                    .with_context(|| format!("handing {} to uid {uid}", group_dir.display()))?;
                std::os::unix::fs::chown(&path, Some(uid), Some(uid))
                    .with_context(|| format!("handing {} to uid {uid}", path.display()))?;
            }
        }
    }
    write_file(&dir.join("load.sh"), LOADER_SH, 0o755)
}

fn load_or_generate(
    canonical_dir: &Path,
    secret: &Secret,
    generate: &mut dyn FnMut(SecretKind) -> Result<SecretValue>,
) -> Result<SecretValue> {
    let path = canonical_dir.join(secret.canonical);
    let public_path = canonical_dir.join(format!("{}.pub", secret.canonical));
    let read = |path: &Path| {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    };
    let stored = match secret.kind {
        SecretKind::RsaKeyPair if path.exists() && public_path.exists() => {
            Some(SecretValue::Pair {
                private: read(&path)?,
                public: read(&public_path)?,
            })
        }
        SecretKind::RsaKeyPair => None,
        _ if path.exists() => Some(SecretValue::Single(read(&path)?)),
        _ => None,
    };
    if let Some(value) = stored {
        return Ok(value);
    }
    let value =
        generate(secret.kind).with_context(|| format!("generating secret {}", secret.canonical))?;
    match (&value, secret.kind) {
        (SecretValue::Pair { private, public }, SecretKind::RsaKeyPair) => {
            write_file(&path, private, 0o600)?;
            write_file(&public_path, public, 0o600)?;
        }
        (SecretValue::Single(single), kind) if kind != SecretKind::RsaKeyPair => {
            write_file(&path, single, 0o600)?;
        }
        _ => bail!(
            "generator returned the wrong shape for {}",
            secret.canonical
        ),
    }
    Ok(value)
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", dir.display()))
}

/// Write `contents` to `path` through a sibling temp file, so a reader never
/// sees a half-written secret.
fn write_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("opening {}", tmp.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// The production generator: `openssl`, which the init image ships.
fn openssl_secret(kind: SecretKind) -> Result<SecretValue> {
    let run = |args: &[&str], stdin: Option<&str>| -> Result<String> {
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running openssl")?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .context("openssl stdin")?
                .write_all(input.as_bytes())?;
        }
        drop(child.stdin.take());
        let output = child.wait_with_output()?;
        anyhow::ensure!(
            output.status.success(),
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    };
    Ok(match kind {
        SecretKind::Hex32 => SecretValue::Single(run(&["rand", "-hex", "16"], None)?),
        SecretKind::Hex64 => SecretValue::Single(run(&["rand", "-hex", "32"], None)?),
        SecretKind::Base64Key32 => SecretValue::Single(run(&["rand", "-base64", "32"], None)?),
        SecretKind::RsaKeyPair => {
            let private = run(
                &[
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                ],
                None,
            )?;
            let public = run(&["pkey", "-pubout"], Some(&private))?;
            SecretValue::Pair { private, public }
        }
    })
}

// ---------------------------------------------------------------------------
// FusionAuth kickstart
// ---------------------------------------------------------------------------

/// The local kickstart with every local-only identity value replaced by an
/// `#{ENV.*}` reference FusionAuth resolves from its own environment. The
/// application's redirect URLs are left empty: `provision` writes them from
/// `MACRO_PUBLIC_URL` on every start, so a changed origin is picked up.
pub(super) fn kickstart() -> Result<Value> {
    let mut doc = kickstart::build(vec![], POPULATE_JWT_LAMBDA, RECONCILE_LAMBDA, None, None);
    doc["//"] = json!("GENERATED by xtask selfhost-init. Self-host FusionAuth bootstrap.");
    let api_key = doc
        .pointer_mut("/apiKeys/0")
        .context("kickstart has no API key")?;
    api_key["key"] = json!("#{ENV.FUSIONAUTH_API_KEY}");
    api_key["description"] = json!("Macro self-host API key");

    let requests = doc
        .get_mut("requests")
        .and_then(Value::as_array_mut)
        .context("kickstart has no requests")?;
    let mut webhooks = 0;
    let mut seen = BTreeMap::new();
    for request in requests.iter_mut() {
        let url = request["url"].as_str().unwrap_or_default().to_owned();
        let body = &mut request["body"];
        let key = if url.starts_with("/api/key/import/") {
            body["key"]["secret"] = json!("#{ENV.JWT_SECRET_KEY}");
            body["key"]["name"] = json!("JWT Signing Key");
            "signing key"
        } else if url.starts_with("/api/email/template/") {
            body["emailTemplate"]["fromEmail"] = json!("#{ENV.MACRO_MAIL_FROM}");
            body["emailTemplate"]["name"] = json!("Passwordless Login");
            "email template"
        } else if url.starts_with("/api/tenant/") {
            let tenant = &mut body["tenant"];
            tenant["name"] = json!("Macro");
            tenant["issuer"] = json!("#{ENV.ISSUER}");
            tenant["emailConfiguration"]["host"] = json!("mail-relay");
            tenant["emailConfiguration"]["port"] = json!(587);
            tenant["emailConfiguration"]["security"] = json!("NONE");
            tenant["emailConfiguration"]["defaultFromEmail"] = json!("#{ENV.MACRO_MAIL_FROM}");
            tenant["emailConfiguration"]["defaultFromName"] = json!("Macro");
            "tenant"
        } else if url.starts_with("/api/application/") {
            body["application"]["oauthConfiguration"]["clientSecret"] =
                json!("#{ENV.FUSIONAUTH_CLIENT_SECRET_KEY}");
            "application"
        } else if url == "/api/user/registration" {
            body["user"]["email"] = json!("#{ENV.FUSIONAUTH_ADMIN_EMAIL}");
            body["user"]["password"] = json!("#{ENV.FUSIONAUTH_ADMIN_PASSWORD}");
            "admin user"
        } else if url == "/api/webhook" {
            body["webhook"]["headers"]["x-internal-auth-key"] =
                json!("#{ENV.INTERNAL_API_SECRET_KEY}");
            webhooks += 1;
            "webhook"
        } else {
            continue;
        };
        seen.insert(key, ());
    }
    for expected in [
        "signing key",
        "email template",
        "tenant",
        "application",
        "admin user",
        "webhook",
    ] {
        anyhow::ensure!(
            seen.contains_key(expected),
            "the local kickstart no longer has a {expected} request; update selfhost::kickstart"
        );
    }
    anyhow::ensure!(
        webhooks == 2,
        "expected the create and delete user webhooks, found {webhooks}"
    );
    Ok(doc)
}

/// The OAuth redirect URLs the deployment's FusionAuth application accepts.
pub(super) fn redirect_urls(public_url: &str) -> Vec<String> {
    let origin = public_url.trim_end_matches('/');
    [
        "/app",
        "/auth/oauth/redirect",
        "/cognition/mcp/servers/auth/callback",
        "/mcp/oauth/callback",
    ]
    .iter()
    .map(|path| format!("{origin}{path}"))
    .collect()
}

fn bootstrap(secrets_dir: &Path, kickstart_dir: &Path) -> Result<()> {
    write_secrets(secrets_dir, CONTAINER_USERS, &mut openssl_secret)?;
    std::fs::create_dir_all(kickstart_dir)
        .with_context(|| format!("creating {}", kickstart_dir.display()))?;
    let json = serde_json::to_string_pretty(&kickstart()?)? + "\n";
    write_file(&kickstart_dir.join("kickstart.json"), &json, 0o644)?;
    println!("self-host secrets and kickstart are in place");
    Ok(())
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

fn env(name: &'static str) -> Result<String> {
    macro_env_var::read_env(name).with_context(|| format!("{name} must be set"))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")
}

/// Retry `attempt` until it succeeds or [`WAIT_LIMIT`] passes, then fail with
/// its last error.
fn retry<T>(what: &str, mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) if start.elapsed() < WAIT_LIMIT => {
                eprintln!("waiting for {what}: {error:#}");
                std::thread::sleep(RETRY_EVERY);
            }
            Err(error) => return Err(error).with_context(|| format!("giving up on {what}")),
        }
    }
}

fn provision() -> Result<()> {
    let database_url = env("DATABASE_URL")?;
    let aws_url = env("LOCAL_AWS_URL")?;
    let brokers = env("KAFKA_BROKERS")?;
    let fusionauth = FusionAuth {
        base_url: env("FUSIONAUTH_BASE_URL")?,
        api_key: env("FUSIONAUTH_API_KEY")?,
    };
    let public_url = env("MACRO_PUBLIC_URL")?;
    let rt = runtime()?;

    let pool = retry("postgres", || {
        rt.block_on(sqlx::PgPool::connect(&database_url))
            .context("connecting")
    })?;
    rt.block_on(macro_db_migrator::MACRO_DB_MIGRATIONS.run(&pool))
        .context("migrating MacroDB")?;
    rt.block_on(pool.close());
    println!("MacroDB migrated");

    retry("object storage, queues, tables and keys", || {
        rt.block_on(localstack::provision_async(&aws_url))
    })?;
    println!("AWS resources provisioned");

    retry("kafka", || rt.block_on(kafka::provision_async(&brokers)))?;
    println!("Kafka topics created");

    let tenant = format!("/api/tenant/{}", identity::TENANT_ID);
    retry("the FusionAuth kickstart", || {
        let (status, body) = fusionauth.call("GET", &tenant, None)?;
        anyhow::ensure!(status == 200, "tenant lookup returned {status}: {body}");
        Ok(())
    })?;
    fusionauth.apply_redirect_urls(&redirect_urls(&public_url))?;
    println!("FusionAuth redirect URLs point at {public_url}");
    Ok(())
}

fn search(helpers_dir: &Path) -> Result<()> {
    let url = env("OPENSEARCH_URL")?;
    retry("opensearch", || {
        let status = Command::new("curl")
            .args(["-fsS", "-o", "/dev/null", "--max-time", "5", &url])
            .status()
            .context("running curl")?;
        anyhow::ensure!(status.success(), "{url} is not answering");
        Ok(())
    })?;
    let status = Command::new("bun")
        .current_dir(helpers_dir)
        .args(["run", "scripts/create_indices.ts"])
        .env("ENVIRONMENT", "local")
        .env("DRY_RUN", "false")
        .env("OPENSEARCH_URL", &url)
        .env("OPENSEARCH_USERNAME", "macrouser")
        .env("OPENSEARCH_PASSWORD", "local")
        .status()
        .context("running create_indices.ts")?;
    anyhow::ensure!(status.success(), "creating the search indices failed");
    println!("search indices created");
    Ok(())
}

fn sso() -> Result<()> {
    let config: BTreeMap<String, String> = [
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET_KEY",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_IDP_ID",
    ]
    .into_iter()
    .filter_map(|name| macro_env_var::maybe_read_env(name).map(|value| (name.to_string(), value)))
    .collect();
    let google = kickstart::GoogleIdp::from_env(&config);
    let github = kickstart::GithubIdp::from_env(&config);
    if google.is_none() && github.is_none() {
        println!("no SSO identity providers configured");
        return Ok(());
    }
    let fusionauth = FusionAuth {
        base_url: env("FUSIONAUTH_BASE_URL")?,
        api_key: env("FUSIONAUTH_API_KEY")?,
    };
    for request in sso_requests(google.as_ref(), github.as_ref()) {
        fusionauth.upsert(&request.url, &request.body)?;
        println!("configured {}", request.url);
    }
    Ok(())
}

pub(super) struct Upsert {
    pub url: String,
    pub body: Value,
}

/// The identity-provider requests the local kickstart would make for these
/// clients, plus the reconcile lambda the Gmail provider references.
pub(super) fn sso_requests(
    google: Option<&kickstart::GoogleIdp>,
    github: Option<&kickstart::GithubIdp>,
) -> Vec<Upsert> {
    let reconcile = format!("/api/lambda/{}", identity::RECONCILE_LAMBDA_ID);
    let doc = kickstart::build(
        vec![],
        POPULATE_JWT_LAMBDA,
        RECONCILE_LAMBDA,
        google,
        github,
    );
    doc["requests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|request| {
            let url = request["url"].as_str()?;
            (url.starts_with("/api/identity-provider/") || url == reconcile).then(|| Upsert {
                url: url.to_owned(),
                body: request["body"].clone(),
            })
        })
        .collect()
}

/// FusionAuth's admin API, called with the deployment's API key.
struct FusionAuth {
    base_url: String,
    api_key: String,
}

impl FusionAuth {
    /// One API call. Returns the status and body; only transport errors fail.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let mut cmd = Command::new("curl");
        cmd.args(["-sS", "--max-time", "10", "-X", method])
            .args(["-H", &format!("Authorization: {}", self.api_key)])
            .args(["-w", "\n%{http_code}"])
            .arg(&url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if body.is_some() {
            cmd.args([
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ]);
        }
        let mut child = cmd.spawn().context("running curl")?;
        if let Some(body) = body {
            let mut stdin = child.stdin.take().context("curl stdin")?;
            stdin.write_all(&serde_json::to_vec(body)?)?;
        }
        drop(child.stdin.take());
        let output = child.wait_with_output().context("waiting for curl")?;
        anyhow::ensure!(
            output.status.success(),
            "FusionAuth {method} {url}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout)?;
        let (body, status) = text.rsplit_once('\n').unwrap_or(("", text.as_str()));
        let status = status
            .trim()
            .parse()
            .with_context(|| format!("FusionAuth {method} {url}: no status in {text:?}"))?;
        Ok((status, body.to_owned()))
    }

    fn call_ok(&self, method: &str, path: &str, body: Option<&Value>) -> Result<String> {
        let (status, text) = self.call(method, path, body)?;
        anyhow::ensure!(
            (200..300).contains(&status),
            "FusionAuth {method} {path} returned {status}: {text}"
        );
        Ok(text)
    }

    /// Write the application's redirect URLs back whole, like
    /// `fusionauth::apply_redirect_urls` does for a local instance.
    fn apply_redirect_urls(&self, urls: &[String]) -> Result<()> {
        let path = format!("/api/application/{}", identity::APPLICATION_ID);
        let mut application: Value = serde_json::from_str(&self.call_ok("GET", &path, None)?)?;
        let current = application
            .pointer_mut("/application/oauthConfiguration/authorizedRedirectURLs")
            .context("FusionAuth application has no oauthConfiguration.authorizedRedirectURLs")?;
        let wanted = Value::from(urls.to_vec());
        if *current == wanted {
            return Ok(());
        }
        *current = wanted;
        self.call_ok("PUT", &path, Some(&application))?;
        Ok(())
    }

    /// Create the entity at `path`, or replace it when it already exists.
    fn upsert(&self, path: &str, body: &Value) -> Result<()> {
        let (status, text) = self.call("GET", path, None)?;
        let method = match status {
            200 => "PUT",
            404 => "POST",
            _ => bail!("FusionAuth GET {path} returned {status}: {text}"),
        };
        self.call_ok(method, path, Some(body))?;
        Ok(())
    }
}
