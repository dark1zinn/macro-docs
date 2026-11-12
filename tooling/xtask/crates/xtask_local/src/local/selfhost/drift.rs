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
        serde_yaml::from_str(&repo_file("docker-compose.yml")).unwrap();
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
/// product analytics (only document_storage_service needs a PostHog key, set
/// on that service alone).
const EXCLUDED: &[&str] = &[
    "COMPOSE_PROJECT_NAME",
    "FRONTEND_PORT",
    "LOCAL_CONTAINER_IMAGE",
    "LOCAL_CONTAINER_NETWORK",
    "POSTHOG_API_KEY",
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
        "add these local env keys to x-macro-env in docker-compose.yml (or to EXCLUDED): {missing:?}"
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

/// Compose restates the image's CMD (the secrets entrypoint replaces it),
/// adding only the trace-export override.
#[test]
fn sync_command_matches_its_dockerfile() {
    const OTEL_OVERRIDE: &str = " --var OTEL_EXPORTER_OTLP_ENDPOINT:${MACRO_OTEL_HTTP_ENDPOINT:-}";
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
        .map(|part| {
            let part = part.as_str().unwrap().replace("$$", "$");
            part.strip_suffix(OTEL_OVERRIDE)
                .map_or(part.clone(), str::to_owned)
        })
        .collect();
    assert_eq!(restated, image);
}
