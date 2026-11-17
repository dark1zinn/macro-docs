//! Ports the self-host domain depends on.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use roles_and_permissions::domain::model::RoleId;
use uuid::Uuid;

use super::model::{
    AllowedEmail, AuditEntry, AuditQuery, AuditStatus, CapturedMessage, ClaimedInvite, InviteClaim,
    InviteLinkRecord, MailPage, MailQuery, NewAuditEntry, PendingInvite, SelfHostError,
    SignupPolicy, UserRecord,
};

/// Persistence for self-host state.
#[async_trait]
pub trait SelfHostRepo: Send + Sync + 'static {
    /// Whether any account holds the super admin role.
    async fn root_exists(&self) -> anyhow::Result<bool>;

    /// Grants the super admin role to `macro_user_id` if no admin exists yet.
    /// Returns `true` when this call made the user root. Concurrent calls are
    /// serialized, so exactly one caller wins.
    async fn claim_root_admin(&self, macro_user_id: &str) -> anyhow::Result<bool>;

    /// Lists every account, oldest first.
    async fn list_users(&self) -> anyhow::Result<Vec<UserRecord>>;

    /// Finds one account by profile id (`"User".id`).
    async fn find_user(&self, user_id: &str) -> anyhow::Result<Option<UserRecord>>;

    /// Records or clears the disabled marker for a user.
    async fn set_disabled(&self, user_id: &str, disabled: bool, by: &str) -> anyhow::Result<()>;

    /// Revokes the super admin role from `macro_user_id` unless that would leave no
    /// active admin. Returns `false` when refused. Check and removal are atomic.
    async fn revoke_admin_unless_last(&self, macro_user_id: &str) -> anyhow::Result<bool>;

    /// Records the disabled marker for `user_id` unless it is the last active admin.
    /// Returns `false` when refused. Check and marker are atomic.
    async fn mark_disabled_unless_last_admin(
        &self,
        user_id: &str,
        by: &str,
    ) -> anyhow::Result<bool>;

    /// The current signup policy. Defaults to `InviteOnly`.
    async fn get_policy(&self) -> anyhow::Result<SignupPolicy>;

    /// Stores the signup policy.
    async fn set_policy(&self, policy: SignupPolicy, by: &str) -> anyhow::Result<()>;

    /// Lists explicitly allowed signup emails.
    async fn list_allowed_emails(&self) -> anyhow::Result<Vec<AllowedEmail>>;

    /// Adds an allowed signup email. Idempotent; returns `true` when this call added it.
    async fn add_allowed_email(&self, email: &str, by: &str) -> anyhow::Result<bool>;

    /// Records that `email` is being invited now, unless it is not allowed or
    /// was invited less than `interval` ago. Concurrent claims are serialized,
    /// so one invitation goes out.
    async fn claim_invite(&self, email: &str, interval: Duration) -> anyhow::Result<InviteClaim>;

    /// Undoes `claim` after its invitation could not be sent, putting back the
    /// previous invitation time. Does nothing once the address no longer holds
    /// that claim (it was invited again, or removed and added back).
    async fn undo_invite_claim(&self, email: &str, claim: ClaimedInvite) -> anyhow::Result<()>;

    /// Removes an allowed signup email. Idempotent.
    async fn remove_allowed_email(&self, email: &str) -> anyhow::Result<()>;

    /// Removes an allowed signup email that has no recorded invitation.
    /// Returns `false` and keeps it when an invitation went out to it.
    async fn remove_uninvited_allowed_email(&self, email: &str) -> anyhow::Result<bool>;

    /// Whether `email` may sign up under `InviteOnly`: it is allowlisted or has a team invite.
    async fn has_signup_grant(&self, email: &str) -> anyhow::Result<bool>;
}

/// Roles for a user, keyed by macro user id.
#[async_trait]
pub trait RolesPort: Send + Sync + 'static {
    /// Returns the roles held by `macro_user_id`.
    async fn get_roles(&self, macro_user_id: &str) -> anyhow::Result<HashSet<RoleId>>;

    /// Grants roles to `macro_user_id`. Idempotent.
    async fn grant_roles(&self, macro_user_id: &str, roles: &[RoleId]) -> anyhow::Result<()>;
}

/// Account lifecycle in the identity provider.
#[async_trait]
pub trait AccountPort: Send + Sync + 'static {
    /// Activates or deactivates an account. A deactivated account cannot sign in.
    async fn set_active(&self, user_id: &str, active: bool) -> anyhow::Result<()>;
}

/// Append-only record of administrative actions.
#[async_trait]
pub trait AuditLog: Send + Sync + 'static {
    /// Records `entry` as pending and returns its id.
    async fn begin(&self, entry: &NewAuditEntry) -> anyhow::Result<i64>;

    /// Settles a pending entry with its outcome. A settled entry never changes again.
    async fn finish(&self, id: i64, status: &AuditStatus) -> anyhow::Result<()>;

    /// Lists entries newest first. `query.limit` is already clamped.
    async fn list(&self, query: &AuditQuery) -> anyhow::Result<Vec<AuditEntry>>;
}

/// Every workspace's invite links and pending email invites. Changes go
/// through the workspaces' own rules, with `admin` (a Macro user id the domain
/// has confirmed is an instance admin) recorded as the actor.
#[async_trait]
pub trait WorkspaceInvites: Send + Sync + 'static {
    /// Every workspace invite link, newest first.
    async fn list_links(&self) -> anyhow::Result<Vec<InviteLinkRecord>>;

    /// Every pending email invite, newest first.
    async fn list_pending(&self) -> anyhow::Result<Vec<PendingInvite>>;

    /// The workspace's invite link, if it has one.
    async fn find_link(&self, team_id: Uuid) -> anyhow::Result<Option<InviteLinkRecord>>;

    /// One pending email invite.
    async fn find_pending(&self, invite_id: Uuid) -> anyhow::Result<Option<PendingInvite>>;

    /// Turns off the workspace's invite link.
    async fn revoke_link(&self, admin: &str, team_id: Uuid) -> Result<(), SelfHostError>;

    /// Cancels a pending email invite.
    async fn revoke_invite(&self, admin: &str, invite: &PendingInvite)
    -> Result<(), SelfHostError>;

    /// Emails a pending invite again. Returns `false` when it was emailed too
    /// recently and nothing was sent; `now` sends it inside that window too.
    async fn resend_invite(
        &self,
        admin: &str,
        invite: &PendingInvite,
        now: bool,
    ) -> Result<bool, SelfHostError>;
}

/// Invitations to join this server, for people who have no account yet.
#[async_trait]
pub trait ServerInviter: Send + Sync + 'static {
    /// The least time between two invitations to one address.
    fn resend_interval(&self) -> Duration;

    /// Emails `email` an invitation to sign up, sent on behalf of `admin`.
    async fn invite(&self, admin: &str, email: &str) -> anyhow::Result<()>;
}

/// The mail the server sent, held by a local capture instead of delivered.
/// Every method returns [`SelfHostError::Unavailable`] when no capture is set up.
#[async_trait]
pub trait MailCapture: Send + Sync + 'static {
    /// One page of captured messages, newest first.
    async fn list(&self, query: &MailQuery) -> Result<MailPage, SelfHostError>;

    /// One captured message with its bodies.
    async fn get(&self, id: &str) -> Result<Option<CapturedMessage>, SelfHostError>;

    /// Deletes one captured message. Returns `false` when it does not exist.
    async fn delete(&self, id: &str) -> Result<bool, SelfHostError>;

    /// Deletes every captured message.
    async fn clear(&self) -> Result<(), SelfHostError>;
}
