//! Behavior tests for the self-host service, using one in-memory fake for all ports.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use roles_and_permissions::domain::model::RoleId;

use super::model::{AllowedEmail, SelfHostError, SignupPolicy, UserRecord};
use super::ports::{AccountPort, RolesPort, SelfHostRepo};
use super::service::SelfHostService;

#[derive(Default)]
struct State {
    /// Accounts in creation order: (FusionAuth id, email).
    users: Vec<(String, String)>,
    roles: HashMap<String, HashSet<RoleId>>,
    /// Disabled marker, keyed by profile id.
    disabled: HashSet<String>,
    /// Identity provider state, keyed by FusionAuth id.
    active: HashMap<String, bool>,
    policy: Option<SignupPolicy>,
    allowed: Vec<String>,
    invites: Vec<String>,
    /// When set, admin role changes and disable markers are refused, as the
    /// atomic repo does for the last active admin.
    refuse_admin_ops: bool,
    /// When set, identity provider activation fails.
    fail_set_active: bool,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);

/// The profile id (`"User".id`) for an email, as stored by the auth service.
fn profile_id(email: &str) -> String {
    format!("macro|{email}")
}

/// Macro user ids of accounts that hold super admin, are not disabled, and exist.
fn active_admin_ids(state: &State) -> Vec<String> {
    state
        .users
        .iter()
        .map(|(_, email)| profile_id(email))
        .filter(|id| {
            state
                .roles
                .get(id)
                .is_some_and(|r| r.contains(&RoleId::SuperAdmin))
                && !state.disabled.contains(id)
        })
        .collect()
}

impl Fake {
    fn with_users(users: &[(&str, &str)]) -> Self {
        let fake = Self::default();
        for (id, email) in users {
            fake.0
                .lock()
                .unwrap()
                .users
                .push(((*id).into(), (*email).into()));
        }
        fake
    }

    fn grant(&self, email: &str, role: RoleId) {
        self.0
            .lock()
            .unwrap()
            .roles
            .entry(profile_id(email))
            .or_default()
            .insert(role);
    }

    fn set_policy(&self, policy: SignupPolicy) {
        self.0.lock().unwrap().policy = Some(policy);
    }

    fn invite(&self, email: &str) {
        self.0.lock().unwrap().invites.push(email.into());
    }

    fn refuse_admin_ops(&self) {
        self.0.lock().unwrap().refuse_admin_ops = true;
    }

    fn fail_set_active(&self) {
        self.0.lock().unwrap().fail_set_active = true;
    }

    fn is_active(&self, fusionauth_id: &str) -> Option<bool> {
        self.0.lock().unwrap().active.get(fusionauth_id).copied()
    }

    fn has_role(&self, email: &str, role: RoleId) -> bool {
        self.0
            .lock()
            .unwrap()
            .roles
            .get(&profile_id(email))
            .is_some_and(|r| r.contains(&role))
    }

    fn record(state: &State, fusionauth_id: &str, email: &str) -> UserRecord {
        let user_id = profile_id(email);
        let is_admin = state
            .roles
            .get(&user_id)
            .is_some_and(|r| r.contains(&RoleId::SuperAdmin));
        UserRecord {
            disabled: state.disabled.contains(&user_id),
            macro_user_id: user_id.clone(),
            user_id,
            email: email.into(),
            fusionauth_user_id: Some(fusionauth_id.into()),
            created_at: Some(Utc::now()),
            is_admin,
        }
    }
}

#[async_trait]
impl SelfHostRepo for Fake {
    async fn root_exists(&self) -> anyhow::Result<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .roles
            .values()
            .any(|r| r.contains(&RoleId::SuperAdmin)))
    }

    async fn claim_root_admin(&self, macro_user_id: &str) -> anyhow::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state
            .roles
            .values()
            .any(|r| r.contains(&RoleId::SuperAdmin))
        {
            return Ok(false);
        }
        state
            .roles
            .entry(macro_user_id.into())
            .or_default()
            .insert(RoleId::SuperAdmin);
        Ok(true)
    }

    async fn revoke_admin_unless_last(&self, macro_user_id: &str) -> anyhow::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state.refuse_admin_ops {
            return Ok(false);
        }
        let active = active_admin_ids(&state);
        let target_active = active.iter().any(|id| id == macro_user_id);
        let others_active = active.iter().any(|id| id != macro_user_id);
        if target_active && !others_active {
            return Ok(false);
        }
        Ok(state
            .roles
            .get_mut(macro_user_id)
            .is_some_and(|r| r.remove(&RoleId::SuperAdmin)))
    }

    async fn mark_disabled_unless_last_admin(
        &self,
        user_id: &str,
        _by: &str,
    ) -> anyhow::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state.refuse_admin_ops {
            return Ok(false);
        }
        let active = active_admin_ids(&state);
        let target_active = active.iter().any(|id| id == user_id);
        let others_active = active.iter().any(|id| id != user_id);
        if target_active && !others_active {
            return Ok(false);
        }
        state.disabled.insert(user_id.into());
        Ok(true)
    }

    async fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let state = self.0.lock().unwrap();
        Ok(state
            .users
            .iter()
            .map(|(id, email)| Self::record(&state, id, email))
            .collect())
    }

    async fn find_user(&self, user_id: &str) -> anyhow::Result<Option<UserRecord>> {
        let state = self.0.lock().unwrap();
        Ok(state
            .users
            .iter()
            .find(|(_, email)| profile_id(email) == user_id)
            .map(|(id, email)| Self::record(&state, id, email)))
    }

    async fn set_disabled(&self, user_id: &str, disabled: bool, _by: &str) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        if disabled {
            state.disabled.insert(user_id.into());
        } else {
            state.disabled.remove(user_id);
        }
        Ok(())
    }

    async fn get_policy(&self) -> anyhow::Result<SignupPolicy> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .policy
            .unwrap_or(SignupPolicy::InviteOnly))
    }

    async fn set_policy(&self, policy: SignupPolicy, _by: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().policy = Some(policy);
        Ok(())
    }

    async fn list_allowed_emails(&self) -> anyhow::Result<Vec<AllowedEmail>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .allowed
            .iter()
            .map(|email| AllowedEmail {
                email: email.clone(),
                created_at: Utc::now(),
            })
            .collect())
    }

    async fn add_allowed_email(&self, email: &str, _by: &str) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        if !state.allowed.iter().any(|e| e == email) {
            state.allowed.push(email.into());
        }
        Ok(())
    }

    async fn remove_allowed_email(&self, email: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().allowed.retain(|e| e != email);
        Ok(())
    }

    async fn has_signup_grant(&self, email: &str) -> anyhow::Result<bool> {
        let state = self.0.lock().unwrap();
        Ok(state.allowed.iter().any(|e| e == email) || state.invites.iter().any(|e| e == email))
    }
}

#[async_trait]
impl RolesPort for Fake {
    async fn get_roles(&self, macro_user_id: &str) -> anyhow::Result<HashSet<RoleId>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .roles
            .get(macro_user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn grant_roles(&self, macro_user_id: &str, roles: &[RoleId]) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        state
            .roles
            .entry(macro_user_id.into())
            .or_default()
            .extend(roles.iter().cloned());
        Ok(())
    }
}

#[async_trait]
impl AccountPort for Fake {
    async fn set_active(&self, fusionauth_id: &str, active: bool) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fail_set_active {
            anyhow::bail!("identity provider unavailable");
        }
        state.active.insert(fusionauth_id.into(), active);
        Ok(())
    }
}

fn service(f: &Fake) -> SelfHostService<Fake, Fake, Fake> {
    SelfHostService::new(f.clone(), f.clone(), f.clone())
}

#[tokio::test]
async fn first_user_created_becomes_root_and_gets_entitlements() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    let svc = service(&f);

    svc.on_user_created("root@example.com").await.unwrap();

    assert!(f.has_role("root@example.com", RoleId::SuperAdmin));
    assert!(f.has_role("root@example.com", RoleId::ProfessionalSubscriber));
    assert!(f.has_role("root@example.com", RoleId::SubMax));
}

#[tokio::test]
async fn later_users_get_entitlements_but_not_root() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "second@example.com")]);
    let svc = service(&f);

    svc.on_user_created("root@example.com").await.unwrap();
    svc.on_user_created("second@example.com").await.unwrap();

    assert!(!f.has_role("second@example.com", RoleId::SuperAdmin));
    assert!(f.has_role("second@example.com", RoleId::SubMax));
}

#[tokio::test]
async fn backfill_makes_oldest_account_root() {
    let f = Fake::with_users(&[
        ("fa-1", "first@example.com"),
        ("fa-2", "second@example.com"),
    ]);
    let svc = service(&f);

    svc.backfill().await.unwrap();

    assert!(f.has_role("first@example.com", RoleId::SuperAdmin));
    assert!(!f.has_role("second@example.com", RoleId::SuperAdmin));
}

#[tokio::test]
async fn signup_is_open_before_root_exists() {
    let f = Fake::default();
    f.set_policy(SignupPolicy::InviteOnly);
    let svc = service(&f);

    assert!(svc.authorize_signup("anyone@example.com").await.unwrap());
}

#[tokio::test]
async fn invite_only_denies_unlisted_email_after_root() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    assert!(!svc.authorize_signup("stranger@example.com").await.unwrap());
}

#[tokio::test]
async fn invite_only_allows_allowlisted_and_invited_email_case_insensitively() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.invite("invited@example.com");
    let svc = service(&f);
    svc.add_allowed_email("macro|root@example.com", "Listed@Example.com")
        .await
        .unwrap();

    assert!(svc.authorize_signup("LISTED@example.com").await.unwrap());
    assert!(svc.authorize_signup("INVITED@example.com").await.unwrap());
}

#[tokio::test]
async fn open_policy_allows_any_email_after_root() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.set_policy(SignupPolicy::Open);
    let svc = service(&f);

    assert!(svc.authorize_signup("stranger@example.com").await.unwrap());
}

#[tokio::test]
async fn non_admin_cannot_list_users() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "user@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc.list_users("macro|user@example.com").await.unwrap_err();

    assert!(matches!(err, SelfHostError::Forbidden));
}

#[tokio::test]
async fn demoting_the_last_active_admin_conflicts() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc
        .set_admin("macro|root@example.com", "macro|root@example.com", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert!(f.has_role("root@example.com", RoleId::SuperAdmin));
}

#[tokio::test]
async fn demoting_one_of_two_active_admins_succeeds() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "admin@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.grant("admin@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    svc.set_admin("macro|root@example.com", "macro|admin@example.com", false)
        .await
        .unwrap();

    assert!(!f.has_role("admin@example.com", RoleId::SuperAdmin));
    assert!(f.has_role("root@example.com", RoleId::SuperAdmin));
}

#[tokio::test]
async fn refused_demotion_is_a_conflict_and_keeps_the_role() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "admin@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.grant("admin@example.com", RoleId::SuperAdmin);
    f.refuse_admin_ops();
    let svc = service(&f);

    let err = svc
        .set_admin("macro|root@example.com", "macro|admin@example.com", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert!(f.has_role("admin@example.com", RoleId::SuperAdmin));
}

#[tokio::test]
async fn admin_cannot_disable_own_account() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "admin@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.grant("admin@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc
        .set_disabled("macro|root@example.com", "macro|root@example.com", true)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert_eq!(f.is_active("fa-1"), None);
}

#[tokio::test]
async fn disabling_a_user_deactivates_the_identity_by_fusionauth_id() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "user@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    svc.set_disabled("macro|root@example.com", "macro|user@example.com", true)
        .await
        .unwrap();

    assert_eq!(f.is_active("fa-2"), Some(false));
    let users = svc.list_users("macro|root@example.com").await.unwrap();
    assert!(
        users
            .iter()
            .any(|u| u.record.user_id == "macro|user@example.com" && u.record.disabled)
    );
}

#[tokio::test]
async fn enabling_a_user_reactivates_the_identity() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "user@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);
    svc.set_disabled("macro|root@example.com", "macro|user@example.com", true)
        .await
        .unwrap();

    svc.set_disabled("macro|root@example.com", "macro|user@example.com", false)
        .await
        .unwrap();

    assert_eq!(f.is_active("fa-2"), Some(true));
    let users = svc.list_users("macro|root@example.com").await.unwrap();
    assert!(
        users
            .iter()
            .any(|u| u.record.user_id == "macro|user@example.com" && !u.record.disabled)
    );
}

#[tokio::test]
async fn refused_disable_is_a_conflict_and_leaves_the_identity_active() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "user@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.refuse_admin_ops();
    let svc = service(&f);

    let err = svc
        .set_disabled("macro|root@example.com", "macro|user@example.com", true)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert_eq!(f.is_active("fa-2"), None);
}

#[tokio::test]
async fn identity_failure_rolls_back_the_disable_marker() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "user@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.fail_set_active();
    let svc = service(&f);

    let err = svc
        .set_disabled("macro|root@example.com", "macro|user@example.com", true)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Internal(_)));
    let users = svc.list_users("macro|root@example.com").await.unwrap();
    assert!(
        users
            .iter()
            .any(|u| u.record.user_id == "macro|user@example.com" && !u.record.disabled)
    );
}

#[tokio::test]
async fn unknown_user_is_not_found() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc
        .set_disabled("macro|root@example.com", "missing", true)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::NotFound));
}

#[tokio::test]
async fn malformed_signup_email_is_rejected_as_invalid() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc
        .add_allowed_email("macro|root@example.com", "not an email")
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Invalid(_)));
}
