use super::*;

// ---------------------------------------------------------------------------
// Drift between the self-host files and the local stack they derive from
// ---------------------------------------------------------------------------

fn repo_file(path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn compose() -> serde_yaml::Value {
    let mut compose: serde_yaml::Value =
        serde_yaml::from_str(&repo_file("selfhost/docker-compose.yml")).unwrap();
    // Anchors merge into anchors (`<<: *rust` holds `<<: *app`); each pass
    // resolves one level.
    for _ in 0..4 {
        compose.apply_merge().unwrap();
    }
    compose
}

fn keys(mapping: &serde_yaml::Value) -> Vec<String> {
    mapping
        .as_mapping()
        .into_iter()
        .flatten()
        .map(|(key, _)| key.as_str().unwrap().to_owned())
        .collect()
}

fn secret_names(group: &str) -> Vec<&'static str> {
    SECRETS
        .iter()
        .flat_map(|secret| secret.files)
        .filter(|file| file.group == group)
        .map(|file| file.name)
        .collect()
}

/// Keys of the local env the self-host stack deliberately does not set: the
/// local orchestrator's own bookkeeping, the host-Docker sandbox provider, and
/// product analytics. document_storage_service requires a PostHog key and a
/// Meta pixel, so those are set on that service alone; in the shared env they
/// would switch on the auth service's analytics. Also optional features the
/// stack doesn't deploy: hosted-computer billing (no billing in self-host
/// mode) and the passwords vault, which needs an OpenBao server.
const EXCLUDED: &[&str] = &[
    "COMPOSE_PROJECT_NAME",
    "FRONTEND_PORT",
    "LOCAL_CONTAINER_IMAGE",
    "LOCAL_CONTAINER_NETWORK",
    "META_ACCESS_TOKEN",
    "META_PIXEL_ID",
    "OPENBAO_ADDRESS",
    "PASSWORDS_JWT_ISSUER",
    "POSTHOG_API_KEY",
    "STRIPE_COMPUTER_LARGE_MONTHLY_PRICE_ID",
    "STRIPE_COMPUTER_LARGE_YEARLY_PRICE_ID",
    "STRIPE_COMPUTER_STANDARD_MONTHLY_PRICE_ID",
    "STRIPE_COMPUTER_STANDARD_YEARLY_PRICE_ID",
    "STRIPE_COMPUTER_XL_MONTHLY_PRICE_ID",
    "STRIPE_COMPUTER_XL_YEARLY_PRICE_ID",
];

/// A key the local stack starts to need must reach the self-host services too.
#[test]
fn compose_env_covers_the_local_stack_env() {
    use super::super::instance::Instance;
    use super::super::local_env::{LocalEnv, Tunnels};

    let instance = Instance::derive(None, None).unwrap();
    let local = LocalEnv::for_instance(
        super::super::Mode::Local,
        &instance,
        true,
        Tunnels::default(),
    )
    .unwrap();
    let mut local_keys: Vec<String> = local.to_env().into_keys().collect();
    local_keys.extend(local.boot_stub_env().into_keys());

    let compose = compose();
    let compose_keys = keys(&compose["x-macro-env"]);
    let generated = secret_names(APP);
    let missing: Vec<&String> = local_keys
        .iter()
        .filter(|key| {
            !compose_keys.contains(key)
                && !generated.contains(&key.as_str())
                && !EXCLUDED.contains(&key.as_str())
        })
        .collect();
    assert!(
        missing.is_empty(),
        "add these local env keys to x-macro-env in selfhost/docker-compose.yml (or to EXCLUDED): {missing:?}"
    );
}

/// Analytics settings switch on outbound tracking in every service that reads
/// them optionally (a placeholder Meta pixel made the auth service post each
/// signup to graph.facebook.com), so the shared env must never carry them.
#[test]
fn compose_env_keeps_analytics_off() {
    let compose = compose();
    let shared = keys(&compose["x-macro-env"]);
    let present: Vec<&String> = shared
        .iter()
        .filter(|key| {
            key.starts_with("META_") || key.starts_with("POSTHOG_") || key.starts_with("GA_")
        })
        .collect();
    assert!(
        present.is_empty(),
        "set these only on the service that requires them, never in x-macro-env: {present:?}"
    );
}

/// The variable names Coolify reads from a compose `environment:` value. Its
/// parser takes each `${...}` (outside `$${`), ends the name at the first
/// `:-`, `-`, `:?` or `?` outside nested braces, and also reads the
/// references nested in the default (`splitOnOperatorOutsideNested` in
/// Coolify's `bootstrap/helpers/services.php`).
fn coolify_variable_names(value: &str) -> Vec<String> {
    const OPERATORS: [&str; 4] = [":-", "-", ":?", "?"];
    let bytes = value.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while let Some(offset) = value[i..].find("${") {
        let start = i + offset;
        if start > 0 && bytes[start - 1] == b'$' {
            i = start + 2;
            continue;
        }
        let mut depth = 0;
        let mut end = None;
        for (j, byte) in bytes.iter().enumerate().skip(start + 1) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        let content = &value[start + 2..end];
        let mut depth = 0;
        let mut split = None;
        'scan: for (j, byte) in content.bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ if depth == 0 => {
                    for op in OPERATORS {
                        if content[j..].starts_with(op) {
                            split = Some((j, op.len()));
                            break 'scan;
                        }
                    }
                }
                _ => {}
            }
        }
        match split {
            Some((at, len)) => {
                names.push(content[..at].to_owned());
                names.extend(coolify_variable_names(&content[at + len..]));
            }
            None => names.push(content.to_owned()),
        }
        i = end + 1;
    }
    names
}

#[test]
fn coolify_reads_conditional_expansions_as_names() {
    assert_eq!(
        coolify_variable_names("${A:-x}${B:+on,}$${C}"),
        ["A", "B:+on,"]
    );
    assert_eq!(coolify_variable_names("${A:-${B}/x}"), ["A", "B"]);
}

/// Coolify stores every variable an `environment:` value references and
/// refuses a deployment whose names are not identifiers, so values may only
/// use expansions it can split (`${VAR}`, `:-`, `-`, `:?`, `?`). Conditional
/// forms such as `${VAR:+text}` belong in `command:`, which it does not parse.
#[test]
fn compose_env_parses_in_coolify() {
    let compose = compose();
    let identifier = |name: &str| {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let mut bad = Vec::new();
    for (service, definition) in compose["services"].as_mapping().unwrap() {
        for (key, value) in definition["environment"].as_mapping().into_iter().flatten() {
            let Some(value) = value.as_str() else {
                continue;
            };
            for name in coolify_variable_names(value) {
                if !identifier(&name) {
                    bad.push(format!(
                        "{}.{}: {name:?}",
                        service.as_str().unwrap(),
                        key.as_str().unwrap()
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "Coolify can't parse these references: {bad:?}"
    );
}

/// The loader never overrides a set variable, so a secret named in compose
/// would silently replace the generated one.
#[test]
fn compose_env_never_sets_a_generated_secret() {
    let compose = compose();
    let mut checked = 0;
    for (name, service) in compose["services"].as_mapping().unwrap() {
        let Some(group) = service["entrypoint"]
            .as_sequence()
            .and_then(|entrypoint| entrypoint.get(2))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        let generated = secret_names(group);
        assert!(
            !generated.is_empty(),
            "{name:?} loads unknown group {group}"
        );
        let set: Vec<String> = keys(&service["environment"])
            .into_iter()
            .filter(|key| generated.contains(&key.as_str()))
            .collect();
        assert!(set.is_empty(), "{name:?} sets generated secrets {set:?}");
        checked += 1;
    }
    assert!(checked > 10, "only {checked} services load secrets");
}

#[test]
fn gateway_routes_every_frontend_prefix() {
    let caddyfile = repo_file("selfhost/gateway/Caddyfile");
    let missing: Vec<&str> = super::super::proxy::frontend_path_prefixes()
        .into_iter()
        .chain(["/static-file", "/local-storage"])
        .filter(|prefix| !caddyfile.contains(&format!("{prefix}/*")))
        .collect();
    assert!(missing.is_empty(), "the gateway does not route {missing:?}");
}

#[test]
fn gateway_storage_allowlist_matches_buckets() {
    let caddyfile = repo_file("selfhost/gateway/Caddyfile");
    let list = caddyfile
        .split("^/local-storage/(")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .expect("the gateway's /local-storage bucket regexp");
    let mut allowed: Vec<&str> = list.split('|').collect();
    let mut buckets: Vec<&str> = super::super::resources::BUCKETS
        .iter()
        .map(|bucket| bucket.name)
        .collect();
    allowed.sort_unstable();
    buckets.sort_unstable();
    assert_eq!(allowed, buckets);
}

/// Compose restates the image's CMD exactly (the secrets entrypoint replaces it).
#[test]
fn sync_command_matches_its_dockerfile() {
    let dockerfile = repo_file("docker/sync-service.Dockerfile");
    let cmd = dockerfile
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("CMD "))
        .expect("a CMD in the sync Dockerfile");
    let image: Vec<String> = serde_json::from_str(cmd).unwrap();
    let compose = compose();
    let restated: Vec<String> = compose["services"]["sync_service"]["command"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|part| part.as_str().unwrap().replace("$$", "$"))
        .collect();
    assert_eq!(restated, image);
}
