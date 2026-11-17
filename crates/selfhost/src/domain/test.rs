//! Behavior tests for the self-host service, using one in-memory fake for all ports.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use roles_and_permissions::domain::model::RoleId;
use uuid::Uuid;

use super::model::{
    AllowedEmail, AuditAction, AuditEntry, AuditQuery, AuditStatus, BulkFailure, BulkOutcome,
    CapturedMail, CapturedMessage, ClaimedInvite, InviteClaim, InviteLinkRecord, MailPage,
    MailQuery, NewAuditEntry, PendingInvite, SelfHostError, SetupToken, SignupPolicy, UserRecord,
};
use super::ports::{
    AccountPort, AuditLog, MailCapture, RolesPort, SelfHostRepo, ServerInviter, WorkspaceInvites,
};
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
    /// Audit entries in recording order, with their current outcome.
    audit: Vec<(NewAuditEntry, AuditStatus)>,
    /// When set, recording an audit entry fails.
    fail_audit: bool,
    /// The last query the audit log was listed with.
    last_audit_query: Option<AuditQuery>,
    /// Workspace invite links.
    links: Vec<InviteLinkRecord>,
    /// Pending workspace email invites.
    pending: Vec<PendingInvite>,
    /// Invites emailed again, by id.
    resent: Vec<Uuid>,
    /// Invites emailed again inside their resend window, by id.
    resent_now: Vec<Uuid>,
    /// When set, a resend finds the invite inside its resend window.
    resend_too_soon: bool,
    /// Links whose revocation fails, by workspace id.
    failing_links: HashSet<Uuid>,
    /// Server invitations sent, by address.
    server_invites: Vec<String>,
    /// When each allowed address was last sent a server invitation.
    last_invited: HashMap<String, DateTime<Utc>>,
    /// When set, sending a server invitation fails.
    fail_server_invite: bool,
    /// When set, another admin invites the address while this send fails.
    invited_elsewhere_during_send: bool,
    /// Captured outgoing mail, newest first.
    mail: Vec<CapturedMessage>,
    /// When set, the mail capture is not set up.
    mail_off: bool,
    /// The last query the mail capture was listed with.
    last_mail_query: Option<MailQuery>,
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

    fn fail_audit(&self) {
        self.0.lock().unwrap().fail_audit = true;
    }

    /// Recorded audit entries as (actor, action, target, outcome).
    fn audit(&self) -> Vec<(Option<String>, AuditAction, Option<String>, AuditStatus)> {
        self.0
            .lock()
            .unwrap()
            .audit
            .iter()
            .map(|(entry, status)| {
                (
                    entry.actor.clone(),
                    entry.action,
                    entry.target.clone(),
                    status.clone(),
                )
            })
            .collect()
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
        let state = self.0.lock().unwrap();
        Ok(state
            .allowed
            .iter()
            .map(|email| AllowedEmail {
                email: email.clone(),
                created_at: Utc::now(),
                last_invited_at: state.last_invited.get(email).copied(),
            })
            .collect())
    }

    async fn add_allowed_email(&self, email: &str, _by: &str) -> anyhow::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state.allowed.iter().any(|e| e == email) {
            return Ok(false);
        }
        state.allowed.push(email.into());
        Ok(true)
    }

    async fn claim_invite(
        &self,
        email: &str,
        interval: std::time::Duration,
    ) -> anyhow::Result<InviteClaim> {
        let mut state = self.0.lock().unwrap();
        if !state.allowed.iter().any(|e| e == email) {
            return Ok(InviteClaim::NotAllowed);
        }
        let now = Utc::now();
        let previous = state.last_invited.get(email).copied();
        if let Some(last) = previous
            && last + Duration::from_std(interval)? > now
        {
            return Ok(InviteClaim::TooSoon(last + Duration::from_std(interval)?));
        }
        state.last_invited.insert(email.into(), now);
        Ok(InviteClaim::Claimed(ClaimedInvite { previous, at: now }))
    }

    async fn undo_invite_claim(&self, email: &str, claim: ClaimedInvite) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.last_invited.get(email) != Some(&claim.at) {
            return Ok(());
        }
        match claim.previous {
            Some(at) => state.last_invited.insert(email.into(), at),
            None => state.last_invited.remove(email),
        };
        Ok(())
    }

    async fn remove_allowed_email(&self, email: &str) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.allowed.retain(|e| e != email);
        state.last_invited.remove(email);
        Ok(())
    }

    async fn remove_uninvited_allowed_email(&self, email: &str) -> anyhow::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state.last_invited.contains_key(email) {
            return Ok(false);
        }
        state.allowed.retain(|e| e != email);
        Ok(true)
    }

    async fn has_signup_grant(&self, email: &str) -> anyhow::Result<bool> {
        let state = self.0.lock().unwrap();
        Ok(state.allowed.iter().any(|e| e == email) || state.invites.iter().any(|e| e == email))
    }

    async fn invite_link_exists(&self, token: Uuid) -> anyhow::Result<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .links
            .iter()
            .any(|l| l.token == token))
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

#[async_trait]
impl AuditLog for Fake {
    async fn begin(&self, entry: &NewAuditEntry) -> anyhow::Result<i64> {
        let mut state = self.0.lock().unwrap();
        if state.fail_audit {
            anyhow::bail!("audit log unavailable");
        }
        state.audit.push((entry.clone(), AuditStatus::Pending));
        Ok(i64::try_from(state.audit.len())? - 1)
    }

    async fn finish(&self, id: i64, status: &AuditStatus) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        let (_, current) = &mut state.audit[usize::try_from(id)?];
        anyhow::ensure!(
            *current == AuditStatus::Pending,
            "entry {id} already settled"
        );
        *current = status.clone();
        Ok(())
    }

    async fn list(&self, query: &AuditQuery) -> anyhow::Result<Vec<AuditEntry>> {
        let mut state = self.0.lock().unwrap();
        state.last_audit_query = Some(query.clone());
        Ok(Vec::new())
    }
}

#[async_trait]
impl WorkspaceInvites for Fake {
    async fn list_links(&self) -> anyhow::Result<Vec<InviteLinkRecord>> {
        Ok(self.0.lock().unwrap().links.clone())
    }

    async fn list_pending(&self) -> anyhow::Result<Vec<PendingInvite>> {
        Ok(self.0.lock().unwrap().pending.clone())
    }

    async fn find_link(&self, team_id: Uuid) -> anyhow::Result<Option<InviteLinkRecord>> {
        let state = self.0.lock().unwrap();
        Ok(state.links.iter().find(|l| l.team_id == team_id).cloned())
    }

    async fn find_pending(&self, invite_id: Uuid) -> anyhow::Result<Option<PendingInvite>> {
        let state = self.0.lock().unwrap();
        Ok(state
            .pending
            .iter()
            .find(|i| i.invite_id == invite_id)
            .cloned())
    }

    async fn revoke_link(&self, _admin: &str, team_id: Uuid) -> Result<(), SelfHostError> {
        let mut state = self.0.lock().unwrap();
        if state.failing_links.contains(&team_id) {
            return Err(SelfHostError::Internal(anyhow::anyhow!(
                "teams unavailable"
            )));
        }
        state.links.retain(|l| l.team_id != team_id);
        Ok(())
    }

    async fn revoke_invite(
        &self,
        _admin: &str,
        invite: &PendingInvite,
    ) -> Result<(), SelfHostError> {
        self.0
            .lock()
            .unwrap()
            .pending
            .retain(|i| i.invite_id != invite.invite_id);
        Ok(())
    }

    async fn resend_invite(
        &self,
        _admin: &str,
        invite: &PendingInvite,
        now: bool,
    ) -> Result<bool, SelfHostError> {
        let mut state = self.0.lock().unwrap();
        if now {
            state.resent_now.push(invite.invite_id);
        } else if state.resend_too_soon {
            return Ok(false);
        }
        state.resent.push(invite.invite_id);
        Ok(true)
    }
}

/// Server invitations one week apart, like the real email.
const INVITE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

#[async_trait]
impl ServerInviter for Fake {
    fn resend_interval(&self) -> std::time::Duration {
        INVITE_INTERVAL
    }

    async fn invite(&self, _admin: &str, email: &str) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fail_server_invite {
            if state.invited_elsewhere_during_send {
                // Another admin's claim lands after this one, and its email goes out.
                let later = Utc::now() + Duration::seconds(1);
                state.last_invited.insert(email.into(), later);
            }
            anyhow::bail!("notification service unavailable");
        }
        state.server_invites.push(email.into());
        Ok(())
    }
}

/// A captured message to `to`, holding a sign-in code.
fn captured(id: &str, to: &str) -> CapturedMessage {
    CapturedMessage {
        mail: CapturedMail {
            id: id.into(),
            from: "noreply@example.com".into(),
            to: vec![to.into()],
            subject: format!("Message {id}"),
            created_at: Utc::now(),
            snippet: "Your code is 123456".into(),
        },
        text: Some("Your code is 123456".into()),
        html: None,
    }
}

#[async_trait]
impl MailCapture for Fake {
    async fn list(&self, query: &MailQuery) -> Result<MailPage, SelfHostError> {
        let mut state = self.0.lock().unwrap();
        state.last_mail_query = Some(query.clone());
        if state.mail_off {
            return Err(SelfHostError::Unavailable("mail capture is off".into()));
        }
        Ok(MailPage {
            total: u32::try_from(state.mail.len()).unwrap(),
            messages: state.mail.iter().map(|m| m.mail.clone()).collect(),
        })
    }

    async fn get(&self, id: &str) -> Result<Option<CapturedMessage>, SelfHostError> {
        let state = self.0.lock().unwrap();
        Ok(state.mail.iter().find(|m| m.mail.id == id).cloned())
    }

    async fn delete(&self, id: &str) -> Result<bool, SelfHostError> {
        let mut state = self.0.lock().unwrap();
        let before = state.mail.len();
        state.mail.retain(|m| m.mail.id != id);
        Ok(state.mail.len() < before)
    }

    async fn clear(&self) -> Result<(), SelfHostError> {
        self.0.lock().unwrap().mail.clear();
        Ok(())
    }
}

fn service(f: &Fake) -> SelfHostService<Fake, Fake, Fake, Fake, Fake, Fake, Fake> {
    SelfHostService::new(
        f.clone(),
        f.clone(),
        f.clone(),
        f.clone(),
        f.clone(),
        f.clone(),
        f.clone(),
    )
}

const SETUP_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn service_with_setup_token(f: &Fake) -> SelfHostService<Fake, Fake, Fake, Fake, Fake, Fake, Fake> {
    service(f).with_setup_token(SetupToken::parse(SETUP_TOKEN).unwrap())
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

    assert!(
        svc.authorize_signup("anyone@example.com", None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn invite_only_denies_unlisted_email_after_root() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    assert!(
        !svc.authorize_signup("stranger@example.com", None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn invite_only_allows_allowlisted_and_invited_email_case_insensitively() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.invite("invited@example.com");
    let svc = service(&f);
    svc.add_allowed_email("macro|root@example.com", "Listed@Example.com", false)
        .await
        .unwrap();

    assert!(
        svc.authorize_signup("LISTED@example.com", None)
            .await
            .unwrap()
    );
    assert!(
        svc.authorize_signup("INVITED@example.com", None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn open_policy_allows_any_email_after_root() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.set_policy(SignupPolicy::Open);
    let svc = service(&f);

    assert!(
        svc.authorize_signup("stranger@example.com", None)
            .await
            .unwrap()
    );
}

/// A workspace's current invite link lets anyone sign up on an invite-only
/// server; a revoked, unknown or malformed link does not.
#[tokio::test]
async fn invite_only_allows_signup_through_a_current_invite_link() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f.0.lock().unwrap().links = vec![link(1, "Design")];
    let svc = service(&f);
    let current = Uuid::from_u128(101).to_string();

    assert!(
        svc.authorize_signup("stranger@example.com", Some(&current))
            .await
            .unwrap()
    );
    for other in [
        Uuid::from_u128(999).to_string(),
        "not-a-link".into(),
        String::new(),
    ] {
        assert!(
            !svc.authorize_signup("stranger@example.com", Some(&other))
                .await
                .unwrap()
        );
    }

    svc.revoke_invite_link(ROOT, Uuid::from_u128(1))
        .await
        .unwrap();
    assert!(
        !svc.authorize_signup("stranger@example.com", Some(&current))
            .await
            .unwrap()
    );
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

    assert!(matches!(err, SelfHostError::NotFound("user")));
}

#[tokio::test]
async fn malformed_signup_email_is_rejected_as_invalid() {
    let f = Fake::with_users(&[("fa-1", "root@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    let svc = service(&f);

    let err = svc
        .add_allowed_email("macro|root@example.com", "not an email", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Invalid(_)));
}

const ROOT: &str = "macro|root@example.com";
const SECOND: &str = "macro|second@example.com";

fn two_users_with_root() -> Fake {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "second@example.com")]);
    f.grant("root@example.com", RoleId::SuperAdmin);
    f
}

#[tokio::test]
async fn every_admin_action_is_recorded_with_its_actor_target_and_outcome() {
    let f = two_users_with_root();
    let svc = service(&f);

    svc.set_admin(ROOT, SECOND, true).await.unwrap();
    svc.set_admin(ROOT, SECOND, false).await.unwrap();
    svc.set_disabled(ROOT, SECOND, true).await.unwrap();
    svc.set_disabled(ROOT, SECOND, false).await.unwrap();
    svc.set_policy(ROOT, SignupPolicy::Open).await.unwrap();
    svc.add_allowed_email(ROOT, " New@Example.com ", false)
        .await
        .unwrap();
    svc.remove_allowed_email(ROOT, "new@example.com")
        .await
        .unwrap();

    let ok = |action, target: Option<&str>| {
        (
            Some(ROOT.to_owned()),
            action,
            target.map(str::to_owned),
            AuditStatus::Succeeded,
        )
    };
    assert_eq!(
        f.audit(),
        [
            ok(AuditAction::AdminGranted, Some(SECOND)),
            ok(AuditAction::AdminRevoked, Some(SECOND)),
            ok(AuditAction::UserDisabled, Some(SECOND)),
            ok(AuditAction::UserEnabled, Some(SECOND)),
            ok(AuditAction::SignupPolicyChanged, None),
            ok(AuditAction::AllowedEmailAdded, Some("new@example.com")),
            ok(AuditAction::AllowedEmailRemoved, Some("new@example.com")),
        ]
    );
}

#[tokio::test]
async fn the_root_claim_is_recorded_as_a_system_action_once() {
    let f = Fake::with_users(&[("fa-1", "root@example.com"), ("fa-2", "second@example.com")]);
    let svc = service(&f);

    svc.on_user_created("root@example.com").await.unwrap();
    svc.on_user_created("second@example.com").await.unwrap();

    assert_eq!(
        f.audit(),
        [(
            None,
            AuditAction::RootClaimed,
            Some(ROOT.to_owned()),
            AuditStatus::Succeeded
        )]
    );
}

#[tokio::test]
async fn a_refused_action_is_recorded_as_failed_with_the_reason() {
    let f = two_users_with_root();
    let svc = service(&f);

    svc.set_disabled(ROOT, ROOT, true).await.unwrap_err();
    svc.set_admin(ROOT, ROOT, false).await.unwrap_err();

    let outcomes: Vec<_> = f.audit().into_iter().map(|(_, a, _, s)| (a, s)).collect();
    assert_eq!(
        outcomes,
        [
            (
                AuditAction::UserDisabled,
                AuditStatus::Failed("cannot disable your own account".into())
            ),
            (
                AuditAction::AdminRevoked,
                AuditStatus::Failed("cannot demote the last active admin".into())
            ),
        ]
    );
}

#[tokio::test]
async fn an_identity_failure_is_recorded_as_failed() {
    let f = two_users_with_root();
    f.fail_set_active();
    let svc = service(&f);

    svc.set_disabled(ROOT, SECOND, true).await.unwrap_err();

    assert!(matches!(
        f.audit().as_slice(),
        [(_, AuditAction::UserDisabled, _, AuditStatus::Failed(_))]
    ));
}

#[tokio::test]
async fn no_ops_invalid_input_and_non_admin_calls_record_nothing() {
    let f = two_users_with_root();
    let svc = service(&f);

    svc.set_admin(ROOT, ROOT, true).await.unwrap();
    svc.set_disabled(ROOT, SECOND, false).await.unwrap();
    svc.set_policy(ROOT, SignupPolicy::InviteOnly)
        .await
        .unwrap();
    svc.add_allowed_email(ROOT, "not an email", false)
        .await
        .unwrap_err();
    svc.set_admin(SECOND, SECOND, true).await.unwrap_err();

    assert!(f.audit().is_empty());
}

#[tokio::test]
async fn an_action_does_not_run_when_its_entry_cannot_be_recorded() {
    let f = two_users_with_root();
    f.fail_audit();
    let svc = service(&f);

    let err = svc.set_admin(ROOT, SECOND, true).await.unwrap_err();

    assert!(matches!(err, SelfHostError::Internal(_)));
    assert!(!f.has_role("second@example.com", RoleId::SuperAdmin));
}

#[tokio::test]
async fn the_audit_listing_needs_an_admin_and_caps_the_page_size() {
    let f = two_users_with_root();
    let svc = service(&f);

    let err = svc
        .list_audit(SECOND, AuditQuery::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::Forbidden));

    svc.list_audit(
        ROOT,
        AuditQuery {
            search: Some("   ".into()),
            limit: Some(10_000),
            ..AuditQuery::default()
        },
    )
    .await
    .unwrap();
    let query = f.0.lock().unwrap().last_audit_query.clone().unwrap();
    assert_eq!(query.limit, Some(200));
    assert_eq!(query.search, None, "blank search means no filter");
}

fn link(team: u128, name: &str) -> InviteLinkRecord {
    InviteLinkRecord {
        team_id: Uuid::from_u128(team),
        team_name: name.into(),
        token: Uuid::from_u128(team + 100),
        created_at: Utc::now(),
        created_by: Some(SECOND.into()),
    }
}

fn pending(id: u128, team: u128, email: &str) -> PendingInvite {
    let now = Utc::now();
    PendingInvite {
        invite_id: Uuid::from_u128(id),
        team_id: Uuid::from_u128(team),
        team_name: "Design".into(),
        email: email.into(),
        invited_by: SECOND.into(),
        is_agent: false,
        created_at: now,
        last_sent_at: now,
        resendable_at: now + Duration::minutes(10),
    }
}

/// Root admin with two workspace links and two pending invites.
fn with_invites() -> Fake {
    let f = two_users_with_root();
    {
        let mut state = f.0.lock().unwrap();
        state.links = vec![link(1, "Design"), link(2, "Sales")];
        state.pending = vec![
            pending(10, 1, "a@example.com"),
            pending(11, 2, "b@example.com"),
        ];
    }
    f
}

#[tokio::test]
async fn the_admin_sees_every_workspace_invite_and_others_cannot() {
    let f = with_invites();
    let svc = service(&f);

    let overview = svc.list_invites(ROOT).await.unwrap();
    assert_eq!(overview.links.len(), 2);
    assert_eq!(overview.invites.len(), 2);

    let err = svc.list_invites(SECOND).await.unwrap_err();
    assert!(matches!(err, SelfHostError::Forbidden));
    let err = svc
        .revoke_invite(SECOND, Uuid::from_u128(10))
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::Forbidden));
    assert_eq!(
        f.0.lock().unwrap().pending.len(),
        2,
        "nothing was cancelled"
    );
    assert!(f.audit().is_empty());
}

#[tokio::test]
async fn revoking_and_resending_invites_are_audited_against_their_targets() {
    let f = with_invites();
    let svc = service(&f);

    svc.revoke_invite_link(ROOT, Uuid::from_u128(1))
        .await
        .unwrap();
    svc.resend_invite(ROOT, Uuid::from_u128(11), false)
        .await
        .unwrap();
    svc.revoke_invite(ROOT, Uuid::from_u128(10)).await.unwrap();

    let state = f.0.lock().unwrap();
    let remaining: Vec<_> = state.links.iter().map(|l| l.team_id).collect();
    assert_eq!(remaining, [Uuid::from_u128(2)]);
    assert_eq!(state.resent, [Uuid::from_u128(11)]);
    assert_eq!(state.pending.len(), 1);
    drop(state);
    let recorded: Vec<_> = f
        .audit()
        .into_iter()
        .map(|(_, a, t, s)| (a, t, s))
        .collect();
    assert_eq!(
        recorded,
        [
            (
                AuditAction::InviteLinkRevoked,
                Some(Uuid::from_u128(1).to_string()),
                AuditStatus::Succeeded
            ),
            (
                AuditAction::TeamInviteResent,
                Some("b@example.com".into()),
                AuditStatus::Succeeded
            ),
            (
                AuditAction::TeamInviteRevoked,
                Some("a@example.com".into()),
                AuditStatus::Succeeded
            ),
        ]
    );
}

#[tokio::test]
async fn revoking_all_audits_each_item_and_reports_the_count() {
    let f = with_invites();
    let svc = service(&f);

    let all_done = BulkOutcome {
        succeeded: 2,
        failures: Vec::new(),
    };
    assert_eq!(svc.revoke_all_invite_links(ROOT).await.unwrap(), all_done);
    assert_eq!(svc.revoke_all_invites(ROOT).await.unwrap(), all_done);

    let state = f.0.lock().unwrap();
    assert!(state.links.is_empty() && state.pending.is_empty());
    drop(state);
    assert_eq!(f.audit().len(), 4);
}

/// One link failing does not stop the others; the outcome names it and why,
/// and each attempt is audited with its own result.
#[tokio::test]
async fn revoking_all_keeps_going_past_a_failure_and_reports_it() {
    let f = with_invites();
    f.0.lock().unwrap().failing_links.insert(Uuid::from_u128(1));
    let svc = service(&f);

    let outcome = svc.revoke_all_invite_links(ROOT).await.unwrap();

    assert_eq!(
        outcome,
        BulkOutcome {
            succeeded: 1,
            failures: vec![BulkFailure {
                target: "Design".into(),
                error: "teams unavailable".into(),
            }],
        }
    );
    let remaining: Vec<_> =
        f.0.lock()
            .unwrap()
            .links
            .iter()
            .map(|l| l.team_id)
            .collect();
    assert_eq!(remaining, [Uuid::from_u128(1)]);
    let outcomes: Vec<_> = f.audit().into_iter().map(|(_, _, _, s)| s).collect();
    assert_eq!(
        outcomes,
        [
            AuditStatus::Failed("teams unavailable".into()),
            AuditStatus::Succeeded
        ]
    );
}

#[tokio::test]
async fn a_resend_inside_the_window_is_refused_and_recorded_as_failed() {
    let f = with_invites();
    f.0.lock().unwrap().resend_too_soon = true;
    let svc = service(&f);

    let err = svc
        .resend_invite(ROOT, Uuid::from_u128(10), false)
        .await
        .unwrap_err();

    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert!(matches!(
        f.audit().as_slice(),
        [(_, AuditAction::TeamInviteResent, _, AuditStatus::Failed(_))]
    ));
}

/// Resending now sends an invite still inside its window, and the audit entry
/// records that the window was overridden.
#[tokio::test]
async fn an_immediate_resend_overrides_the_window_and_is_recorded_as_such() {
    let f = with_invites();
    f.0.lock().unwrap().resend_too_soon = true;
    let svc = service(&f);

    svc.resend_invite(ROOT, Uuid::from_u128(10), true)
        .await
        .unwrap();

    let state = f.0.lock().unwrap();
    assert_eq!(state.resent_now, [Uuid::from_u128(10)]);
    let [(entry, status)] = state.audit.as_slice() else {
        panic!("expected one audit entry, got {:?}", state.audit);
    };
    assert_eq!(entry.action, AuditAction::TeamInviteResent);
    assert_eq!(entry.details["immediate"], true);
    assert_eq!(*status, AuditStatus::Succeeded);
}

#[tokio::test]
async fn unknown_invites_and_links_are_not_found_and_not_audited() {
    let f = with_invites();
    let svc = service(&f);

    let err = svc
        .resend_invite(ROOT, Uuid::from_u128(99), true)
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::NotFound("invite")));
    let err = svc
        .revoke_invite_link(ROOT, Uuid::from_u128(99))
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::NotFound("invite link")));
    assert!(f.audit().is_empty());
}

#[tokio::test]
async fn allowing_an_email_can_send_a_server_invitation() {
    let f = two_users_with_root();
    let svc = service(&f);

    svc.add_allowed_email(ROOT, "Quiet@Example.com", false)
        .await
        .unwrap();
    svc.add_allowed_email(ROOT, "Told@Example.com", true)
        .await
        .unwrap();
    svc.invite_allowed_email(ROOT, "quiet@example.com")
        .await
        .unwrap();

    assert_eq!(
        f.0.lock().unwrap().server_invites,
        ["told@example.com", "quiet@example.com"]
    );
    let invited: Vec<_> = f
        .audit()
        .into_iter()
        .filter(|(_, a, _, _)| *a == AuditAction::AllowedEmailInvited)
        .map(|(_, _, t, s)| (t, s))
        .collect();
    assert_eq!(
        invited,
        [
            (Some("told@example.com".into()), AuditStatus::Succeeded),
            (Some("quiet@example.com".into()), AuditStatus::Succeeded),
        ]
    );
}

/// Refusals are audited too: an address that is not allowed, and one that
/// already has an account.
#[tokio::test]
async fn server_invitations_need_an_allowed_address_without_an_account() {
    let f = two_users_with_root();
    let svc = service(&f);

    let err = svc
        .invite_allowed_email(ROOT, "stranger@example.com")
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::NotFound("allowed email")));

    svc.add_allowed_email(ROOT, "second@example.com", false)
        .await
        .unwrap();
    let err = svc
        .invite_allowed_email(ROOT, "second@example.com")
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::Conflict(_)));
    assert!(f.0.lock().unwrap().server_invites.is_empty());
    let invited: Vec<_> = f
        .audit()
        .into_iter()
        .filter(|(_, a, _, _)| *a == AuditAction::AllowedEmailInvited)
        .map(|(_, _, t, s)| (t, s))
        .collect();
    assert_eq!(
        invited,
        [
            (
                Some("stranger@example.com".into()),
                AuditStatus::Failed("allowed email not found".into())
            ),
            (
                Some("second@example.com".into()),
                AuditStatus::Failed("this address already has an account".into())
            ),
        ]
    );
}

/// A second invitation within the interval is refused with when it opens,
/// rather than reported sent and dropped; after the interval it goes out.
#[tokio::test]
async fn an_address_is_invited_at_most_once_per_interval() {
    let f = two_users_with_root();
    let svc = service(&f);
    svc.add_allowed_email(ROOT, "new@example.com", true)
        .await
        .unwrap();

    let err = svc
        .invite_allowed_email(ROOT, "new@example.com")
        .await
        .unwrap_err();
    let SelfHostError::Conflict(message) = err else {
        panic!("expected a conflict, got {err:?}");
    };
    let invited_at = f.0.lock().unwrap().last_invited["new@example.com"];
    let opens = invited_at + Duration::from_std(INVITE_INTERVAL).unwrap();
    assert!(message.contains(&opens.to_rfc3339()), "{message}");
    assert_eq!(f.0.lock().unwrap().server_invites, ["new@example.com"]);

    f.0.lock().unwrap().last_invited.insert(
        "new@example.com".into(),
        invited_at - Duration::from_std(INVITE_INTERVAL).unwrap(),
    );
    svc.invite_allowed_email(ROOT, "new@example.com")
        .await
        .unwrap();
    assert_eq!(
        f.0.lock().unwrap().server_invites,
        ["new@example.com", "new@example.com"]
    );
}

/// When the invitation cannot be sent, nothing is left half done: the
/// address's invitation time is put back, an address just allowed for it is
/// taken off the allowlist (audited), and one allowed earlier stays.
#[tokio::test]
async fn a_failed_invitation_leaves_no_trace_of_itself() {
    let f = two_users_with_root();
    let svc = service(&f);
    svc.add_allowed_email(ROOT, "earlier@example.com", false)
        .await
        .unwrap();
    f.0.lock().unwrap().fail_server_invite = true;

    for email in ["fresh@example.com", "earlier@example.com"] {
        let err = svc.add_allowed_email(ROOT, email, true).await.unwrap_err();
        assert!(
            matches!(&err, SelfHostError::Internal(e) if e.to_string() == "notification service unavailable"),
            "the caller gets the send failure: {err:?}"
        );
    }

    {
        let state = f.0.lock().unwrap();
        assert_eq!(state.allowed, ["earlier@example.com"]);
        assert!(state.last_invited.is_empty());
    }
    let recorded: Vec<_> = f
        .audit()
        .into_iter()
        .map(|(_, a, t, s)| (a, t.unwrap(), s == AuditStatus::Succeeded))
        .collect();
    assert_eq!(
        recorded,
        [
            (
                AuditAction::AllowedEmailAdded,
                "earlier@example.com".into(),
                true
            ),
            (
                AuditAction::AllowedEmailAdded,
                "fresh@example.com".into(),
                true
            ),
            (
                AuditAction::AllowedEmailInvited,
                "fresh@example.com".into(),
                false
            ),
            (
                AuditAction::AllowedEmailRemoved,
                "fresh@example.com".into(),
                true
            ),
            (
                AuditAction::AllowedEmailAdded,
                "earlier@example.com".into(),
                true
            ),
            (
                AuditAction::AllowedEmailInvited,
                "earlier@example.com".into(),
                false
            ),
        ]
    );

    f.0.lock().unwrap().fail_server_invite = false;
    svc.invite_allowed_email(ROOT, "earlier@example.com")
        .await
        .unwrap();
}

/// A failed invitation's undo never erases another admin's invitation that
/// went out meanwhile: its time stays, and the address stays allowed, with
/// the refused removal audited.
#[tokio::test]
async fn a_failed_invitation_keeps_a_concurrent_successful_one() {
    let f = two_users_with_root();
    {
        let mut state = f.0.lock().unwrap();
        state.fail_server_invite = true;
        state.invited_elsewhere_during_send = true;
    }
    let svc = service(&f);

    let err = svc
        .add_allowed_email(ROOT, "fresh@example.com", true)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SelfHostError::Internal(_)),
        "the caller gets the send failure, not the kept address: {err:?}"
    );

    {
        let state = f.0.lock().unwrap();
        assert_eq!(state.allowed, ["fresh@example.com"]);
        assert!(state.last_invited.contains_key("fresh@example.com"));
    }
    assert!(matches!(
        f.audit().last(),
        Some((
            _,
            AuditAction::AllowedEmailRemoved,
            _,
            AuditStatus::Failed(_)
        ))
    ));
}

// -- Setup token --

/// With a setup token, being created first no longer makes an account root,
/// at sign-up or at the startup backfill.
#[tokio::test]
async fn a_setup_token_reserves_root() {
    let f = Fake::with_users(&[("fa-1", "stranger@example.com")]);
    let svc = service_with_setup_token(&f);

    svc.on_user_created("stranger@example.com").await.unwrap();
    svc.backfill().await.unwrap();

    assert!(!f.has_role("stranger@example.com", RoleId::SuperAdmin));
    assert!(f.has_role("stranger@example.com", RoleId::SubMax));
    assert!(f.audit().is_empty());
}

/// The setup token is accepted only as itself, only while root is unclaimed,
/// and the account that signs in with it becomes root, audited as such.
#[tokio::test]
async fn signing_in_with_the_setup_token_claims_root_once() {
    let f = Fake::with_users(&[("fa-1", "owner@example.com"), ("fa-2", "other@example.com")]);
    let svc = service_with_setup_token(&f);
    svc.on_user_created("owner@example.com").await.unwrap();

    assert!(!svc.setup_token_accepted("123456").await.unwrap());
    assert!(!svc.setup_token_accepted(&SETUP_TOKEN[1..]).await.unwrap());
    assert!(svc.setup_token_accepted(SETUP_TOKEN).await.unwrap());
    assert!(
        svc.claim_root_with_setup_token("owner@example.com")
            .await
            .unwrap()
    );

    assert!(f.has_role("owner@example.com", RoleId::SuperAdmin));
    assert!(!svc.setup_token_accepted(SETUP_TOKEN).await.unwrap());
    assert!(
        !svc.claim_root_with_setup_token("other@example.com")
            .await
            .unwrap()
    );
    assert!(!f.has_role("other@example.com", RoleId::SuperAdmin));
    let state = f.0.lock().unwrap();
    let [(entry, AuditStatus::Succeeded)] = state.audit.as_slice() else {
        panic!("expected one recorded claim, got {:?}", state.audit);
    };
    assert_eq!(entry.action, AuditAction::RootClaimed);
    assert_eq!(entry.target.as_deref(), Some("macro|owner@example.com"));
    assert_eq!(entry.details["via"], "setup token");
}

/// Without a configured token nothing stands in for the emailed code.
#[tokio::test]
async fn without_a_setup_token_no_code_substitute_exists() {
    let f = Fake::with_users(&[("fa-1", "owner@example.com")]);
    let svc = service(&f);

    assert!(!svc.setup_token_accepted(SETUP_TOKEN).await.unwrap());
    assert!(
        !svc.claim_root_with_setup_token("owner@example.com")
            .await
            .unwrap()
    );
}

/// Tokens too short to resist guessing, or that would change in a URL, are refused.
#[test]
fn setup_tokens_must_be_long_and_url_safe() {
    assert!(SetupToken::parse(SETUP_TOKEN).is_ok());
    assert!(SetupToken::parse(&SETUP_TOKEN[1..]).is_err());
    assert!(SetupToken::parse(&format!("{SETUP_TOKEN}/x")).is_err());
    assert!(SetupToken::parse(&format!("{SETUP_TOKEN} x")).is_err());
}

// -- Captured mail --

fn with_mail() -> Fake {
    let f = two_users_with_root();
    f.0.lock().unwrap().mail = vec![
        captured("m2", "new@example.com"),
        captured("m1", "other@example.com"),
    ];
    f
}

/// Only admins read captured mail; the page size is bounded and a blank
/// search means none.
#[tokio::test]
async fn only_admins_read_captured_mail() {
    let f = with_mail();
    let svc = service(&f);

    let page = svc
        .list_captured_mail(
            ROOT,
            MailQuery {
                search: Some("  ".into()),
                start: 0,
                limit: Some(10_000),
            },
        )
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    let query = f.0.lock().unwrap().last_mail_query.clone().unwrap();
    assert_eq!((query.search, query.limit), (None, Some(200)));
    let message = svc.captured_message(ROOT, "m2").await.unwrap();
    assert_eq!(message.text.as_deref(), Some("Your code is 123456"));

    for err in [
        svc.list_captured_mail(SECOND, MailQuery::default())
            .await
            .unwrap_err(),
        svc.captured_message(SECOND, "m2").await.unwrap_err(),
        svc.delete_captured_mail(SECOND, "m2").await.unwrap_err(),
        svc.clear_captured_mail(SECOND).await.unwrap_err(),
    ] {
        assert!(matches!(err, SelfHostError::Forbidden), "{err:?}");
    }
    assert_eq!(f.0.lock().unwrap().mail.len(), 2);
}

/// Deleting captured mail is audited against its recipients; an unknown
/// message is not found and leaves no entry.
#[tokio::test]
async fn deleting_captured_mail_is_audited() {
    let f = with_mail();
    let svc = service(&f);

    let err = svc.delete_captured_mail(ROOT, "missing").await.unwrap_err();
    assert!(matches!(err, SelfHostError::NotFound("message")));
    assert!(f.audit().is_empty());

    svc.delete_captured_mail(ROOT, "m2").await.unwrap();
    svc.clear_captured_mail(ROOT).await.unwrap();

    assert!(f.0.lock().unwrap().mail.is_empty());
    let recorded: Vec<_> = f
        .audit()
        .into_iter()
        .map(|(_, a, t, s)| (a, t, s))
        .collect();
    assert_eq!(
        recorded,
        [
            (
                AuditAction::CapturedMailDeleted,
                Some("new@example.com".into()),
                AuditStatus::Succeeded
            ),
            (
                AuditAction::CapturedMailCleared,
                None,
                AuditStatus::Succeeded
            ),
        ]
    );
}

/// A server without a mail capture says so as unavailable, not as an error.
#[tokio::test]
async fn an_absent_mail_capture_is_unavailable() {
    let f = with_mail();
    f.0.lock().unwrap().mail_off = true;
    let svc = service(&f);

    let err = svc
        .list_captured_mail(ROOT, MailQuery::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SelfHostError::Unavailable(_)));
}
