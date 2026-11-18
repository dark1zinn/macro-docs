use std::process::Command;

use super::*;

/// A generator that hands out distinct, recognisable values and counts calls.
fn counting(calls: &mut usize) -> impl FnMut(SecretKind) -> Result<SecretValue> + '_ {
    move |kind| {
        *calls += 1;
        Ok(match kind {
            SecretKind::RsaKeyPair => SecretValue::Pair {
                private: format!("private-key-{calls}\nsecond line"),
                public: format!("public-key-{calls}\nsecond line"),
            },
            _ => SecretValue::Single(format!("value{calls}")),
        })
    }
}

fn read(dir: &Path, group: &str, name: &str) -> String {
    std::fs::read_to_string(dir.join(group).join(name)).unwrap()
}

fn every_file(dir: &Path) -> BTreeMap<String, String> {
    SECRETS
        .iter()
        .flat_map(|secret| secret.files)
        .map(|file| {
            (
                format!("{}/{}", file.group, file.name),
                read(dir, file.group, file.name),
            )
        })
        .collect()
}

#[test]
fn secrets_are_generated_once_and_survive_reruns() {
    let dir = tempfile::tempdir().unwrap();
    let mut calls = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut calls)).unwrap();
    assert_eq!(calls, SECRETS.len());
    let first = every_file(dir.path());

    let mut again = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut again)).unwrap();
    assert_eq!(again, 0, "a rerun must not generate anything");
    assert_eq!(every_file(dir.path()), first);
}

#[test]
fn a_missing_alias_is_restored_from_the_stored_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut calls = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut calls)).unwrap();
    let internal = read(dir.path(), APP, "INTERNAL_API_SECRET_KEY");
    std::fs::remove_file(dir.path().join(APP).join("SYNC_SERVICE_AUTH_KEY")).unwrap();

    let mut again = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut again)).unwrap();
    assert_eq!(again, 0);
    assert_eq!(read(dir.path(), APP, "SYNC_SERVICE_AUTH_KEY"), internal);
}

#[test]
fn database_urls_embed_the_postgres_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut calls = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut calls)).unwrap();
    let password = read(dir.path(), POSTGRES, "POSTGRES_PASSWORD");
    assert_eq!(
        read(dir.path(), APP, "DATABASE_URL"),
        format!("postgres://macro:{password}@postgres:5432/macrodb")
    );
    assert_eq!(
        read(dir.path(), APP, "DATABASE_URL"),
        read(dir.path(), APP, "MACRO_DB_URL")
    );
}

#[test]
fn shared_secrets_agree_across_containers() {
    let dir = tempfile::tempdir().unwrap();
    let mut calls = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut calls)).unwrap();
    // The FusionAuth webhook header must equal the services' internal key,
    // and FusionAuth signs tokens with the key the services verify.
    for (app, fusionauth) in [
        ("INTERNAL_API_SECRET_KEY", "INTERNAL_API_SECRET_KEY"),
        ("JWT_SECRET_KEY", "JWT_SECRET_KEY"),
        ("FUSIONAUTH_API_KEY", "FUSIONAUTH_API_KEY"),
        (
            "FUSIONAUTH_CLIENT_SECRET_KEY",
            "FUSIONAUTH_CLIENT_SECRET_KEY",
        ),
    ] {
        assert_eq!(
            read(dir.path(), APP, app),
            read(dir.path(), FUSIONAUTH, fusionauth)
        );
    }
    assert_eq!(
        read(dir.path(), FUSIONAUTH_DB, "POSTGRES_PASSWORD"),
        read(dir.path(), FUSIONAUTH, "DATABASE_PASSWORD")
    );
}

fn load(dir: &Path, script: &str, extra_env: &[(&str, &str)]) -> String {
    let output = Command::new("sh")
        .arg(dir.join("load.sh"))
        .args([APP, "sh", "-c", script])
        .env_remove("JWT_SECRET_KEY")
        .env_remove("MACRO_API_TOKEN_PUBLIC_KEY")
        .env("MACRO_SECRETS_DIR", dir)
        .envs(extra_env.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn the_loader_exports_secrets_unless_already_set() {
    let dir = tempfile::tempdir().unwrap();
    let mut calls = 0;
    write_secrets(dir.path(), &[], &mut counting(&mut calls)).unwrap();

    assert_eq!(
        load(dir.path(), r#"printf %s "$JWT_SECRET_KEY""#, &[]),
        read(dir.path(), APP, "JWT_SECRET_KEY")
    );
    assert_eq!(
        load(
            dir.path(),
            r#"printf %s "$JWT_SECRET_KEY""#,
            &[("JWT_SECRET_KEY", "explicit")]
        ),
        "explicit"
    );
    assert_eq!(
        load(
            dir.path(),
            r#"printf %s "$MACRO_API_TOKEN_PUBLIC_KEY""#,
            &[]
        ),
        read(dir.path(), APP, "MACRO_API_TOKEN_PUBLIC_KEY"),
        "multi-line PEMs survive the loader"
    );
}

#[test]
fn the_kickstart_carries_no_local_identity() {
    let doc = kickstart().unwrap();
    let text = serde_json::to_string(&doc).unwrap();
    for local in [
        identity::JWT_SECRET,
        identity::CLIENT_SECRET,
        identity::FUSIONAUTH_API_KEY,
        identity::ISSUER,
        identity::MAIL_FROM,
        "mailpit",
        "admin@macro.com",
        "macroIsGreat!",
        "localhost",
    ] {
        assert!(!text.contains(local), "kickstart still contains {local:?}");
    }
    let webhooks: Vec<&Value> = doc["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|request| request["url"] == "/api/webhook")
        .collect();
    assert_eq!(webhooks.len(), 2);
    for webhook in webhooks {
        assert_eq!(
            webhook["body"]["webhook"]["headers"]["x-internal-auth-key"],
            "#{ENV.INTERNAL_API_SECRET_KEY}"
        );
    }
}

#[test]
fn redirect_urls_follow_the_public_origin() {
    assert_eq!(
        redirect_urls("https://docs.example.com/"),
        [
            "https://docs.example.com/app",
            "https://docs.example.com/auth/oauth/redirect",
            "https://docs.example.com/cognition/mcp/servers/auth/callback",
            "https://docs.example.com/mcp/oauth/callback",
        ]
    );
}

#[test]
fn sso_requests_exist_only_for_configured_providers() {
    assert!(sso_requests(None, None).is_empty());
    let github = kickstart::GithubIdp {
        client_id: "client".into(),
        client_secret: "secret".into(),
        idp_id: identity::GITHUB_IDP_ID.into(),
    };
    let urls: Vec<String> = sso_requests(None, Some(&github))
        .into_iter()
        .map(|request| request.url)
        .collect();
    assert_eq!(
        urls,
        [format!(
            "/api/identity-provider/{}",
            identity::GITHUB_IDP_ID
        )]
    );
}

/// The agent harness resolves `google_gmail` by name at startup, so it must
/// exist even without Google; it stays disabled until `sso` configures it.
#[test]
fn placeholder_google_providers_exist_and_are_disabled() {
    let requests = placeholder_google_requests();
    let gmail = requests
        .iter()
        .find(|request| request.body["identityProvider"]["name"] == "google_gmail")
        .expect("a google_gmail provider");
    assert_eq!(
        gmail.url,
        format!("/api/identity-provider/{}", identity::GOOGLE_GMAIL_IDP_ID)
    );
    let reconcile = format!("/api/lambda/{}", identity::RECONCILE_LAMBDA_ID);
    assert!(requests.iter().any(|request| request.url == reconcile));
    for request in requests
        .iter()
        .filter(|r| r.url.starts_with("/api/identity-provider/"))
    {
        assert_eq!(
            request.body["identityProvider"]["enabled"], false,
            "{}",
            request.url
        );
    }
}

/// A provider named like the placeholder but under another id (made by hand)
/// must not fail provisioning; other validation errors still must.
#[test]
fn duplicate_name_errors_are_recognised() {
    let duplicate = r#"{"fieldErrors":{"identityProvider.name":[{"code":"[duplicate]identityProvider.name","message":"An identity provider with name [google_gmail] already exists."}]},"generalErrors":[]}"#;
    assert!(is_duplicate_name(duplicate));
    let other = r#"{"fieldErrors":{"identityProvider.oauth2.client_id":[{"code":"[blank]identityProvider.oauth2.client_id","message":"required"}]}}"#;
    assert!(!is_duplicate_name(other));
    assert!(!is_duplicate_name("not json"));
}

/// Init can complete every kickstart request it repeats, from env it has.
#[test]
fn every_kickstart_request_can_be_completed_by_init() {
    let known = |name: &str| KICKSTART_ENV.contains(&name).then(|| "x".to_owned());
    for request in kickstart().unwrap()["requests"].as_array().unwrap() {
        let method = request["method"].as_str().unwrap();
        let url = request["url"].as_str().unwrap();
        let step = kickstart_step(method, url).unwrap();
        if step != KickstartStep::Skip {
            let mut body = request["body"].clone();
            resolve_env(&mut body, &known).unwrap_or_else(|e| panic!("{method} {url}: {e:#}"));
        }
    }
}

#[test]
fn resolve_env_substitutes_and_fails_on_unknown_names() {
    let lookup = |name: &str| (name == "A").then(|| "1".to_owned());
    let mut value = json!({"x": ["pre-#{ENV.A}-#{ENV.A}"]});
    resolve_env(&mut value, &lookup).unwrap();
    assert_eq!(value, json!({"x": ["pre-1-1"]}));
    assert!(resolve_env(&mut json!("#{ENV.B}"), &lookup).is_err());
}

#[test]
fn the_key_import_is_probed_by_key_id() {
    assert_eq!(
        kickstart_step("POST", "/api/key/import/abc").unwrap(),
        KickstartStep::Create {
            probe: "/api/key/abc".into()
        }
    );
}
