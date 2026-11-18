//! Plain data types for self-host administration.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Signup policy that applies once a root admin exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupPolicy {
    /// Anyone may create an account.
    Open,
    /// Only allowlisted or team-invited emails may create an account.
    InviteOnly,
}

impl SignupPolicy {
    /// The stored string form of the policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InviteOnly => "invite_only",
        }
    }

    /// Parses the stored or API string form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "invite_only" => Some(Self::InviteOnly),
            _ => None,
        }
    }
}

/// A user account as seen by the self-host admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// Profile id (`"User".id`, `macro|<email>`).
    pub user_id: String,
    /// Account email as stored.
    pub email: String,
    /// Macro user id derived from the email (`macro|<email>`).
    pub macro_user_id: String,
    /// FusionAuth user id (`"User".macro_user_id`), absent when the account has none.
    pub fusionauth_user_id: Option<String>,
    /// Creation time, if recorded for this account.
    pub created_at: Option<DateTime<Utc>>,
    /// Whether the account holds the super admin role.
    pub is_admin: bool,
    /// Whether the account has been disabled by an admin.
    pub disabled: bool,
}

/// A user as returned to an admin listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    /// The user record.
    pub record: UserRecord,
    /// Whether this user is the caller.
    pub is_self: bool,
}

/// An email granted permission to sign up under `InviteOnly`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedEmail {
    /// Lowercased email address.
    pub email: String,
    /// When the grant was created.
    pub created_at: DateTime<Utc>,
    /// When the address was last sent a server invitation, if ever.
    pub last_invited_at: Option<DateTime<Utc>>,
}

/// The outcome of claiming the right to send an allowed email a server invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteClaim {
    /// The address may be invited now, and is recorded as invited at `at`.
    Claimed(ClaimedInvite),
    /// The address was invited too recently; it can be invited again at this time.
    TooSoon(DateTime<Utc>),
    /// The address is not on the allowlist.
    NotAllowed,
}

/// A claimed invitation, with what to put back if its send fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedInvite {
    /// The previous invitation time.
    pub previous: Option<DateTime<Utc>>,
    /// The invitation time this claim recorded. Undoing the claim only
    /// applies while the address still holds it, so a later claim survives.
    pub at: DateTime<Utc>,
}

/// What a bulk admin action did: how many items succeeded, and why the rest failed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkOutcome {
    /// Items the action succeeded on.
    pub succeeded: usize,
    /// Items it failed on, each with its reason.
    pub failures: Vec<BulkFailure>,
}

/// One item a bulk admin action failed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkFailure {
    /// What the item was: a workspace name, or an invited address.
    pub target: String,
    /// Why it failed.
    pub error: String,
}

/// A workspace's shareable invite link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteLinkRecord {
    /// The workspace (team) id.
    pub team_id: Uuid,
    /// The workspace's name.
    pub team_name: String,
    /// The link's secret token.
    pub token: Uuid,
    /// When the link was created or last replaced.
    pub created_at: DateTime<Utc>,
    /// Macro user id of whoever created or last replaced it; unknown for old links.
    pub created_by: Option<String>,
}

/// An email invite to a workspace nobody has answered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvite {
    /// The invite id.
    pub invite_id: Uuid,
    /// The workspace (team) id.
    pub team_id: Uuid,
    /// The workspace's name.
    pub team_name: String,
    /// The invited address.
    pub email: String,
    /// Macro user id of the inviter.
    pub invited_by: String,
    /// Whether the invite is for an agent account.
    pub is_agent: bool,
    /// When the invite was created.
    pub created_at: DateTime<Utc>,
    /// When the invite was last emailed.
    pub last_sent_at: DateTime<Utc>,
    /// The earliest time emailing it again is not rate-limited. An admin can
    /// override it and resend sooner.
    pub resendable_at: DateTime<Utc>,
}

/// Every way into the server: workspace invite links and pending email invites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvitesOverview {
    /// Invite links, newest first.
    pub links: Vec<InviteLinkRecord>,
    /// Pending email invites, newest first.
    pub invites: Vec<PendingInvite>,
}

/// The secret an operator configures so that only they can claim root: while
/// no root admin exists, signing in with it instead of the emailed code makes
/// that account root.
#[derive(Clone)]
pub struct SetupToken(String);

impl SetupToken {
    /// The shortest accepted token; long enough that guessing is hopeless.
    pub const MIN_LEN: usize = 32;

    /// Validates a configured token: at least [`Self::MIN_LEN`] characters of
    /// letters, digits, `-` or `_`, so it travels unchanged in a URL path.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let token = raw.trim();
        if token.len() < Self::MIN_LEN {
            return Err(format!(
                "the setup token must be at least {} characters",
                Self::MIN_LEN
            ));
        }
        if !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("the setup token may only contain letters, digits, '-' and '_'".into());
        }
        Ok(Self(token.to_owned()))
    }

    /// Whether `candidate` is this token, compared in constant time.
    pub fn matches(&self, candidate: &str) -> bool {
        let (expected, given) = (self.0.as_bytes(), candidate.as_bytes());
        expected.len() == given.len()
            && expected
                .iter()
                .zip(given)
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
    }
}

impl std::fmt::Debug for SetupToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupToken(..)")
    }
}

/// Which captured messages to list, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailQuery {
    /// Only messages matching this search (sender, recipient, subject or body).
    pub search: Option<String>,
    /// How many newer messages to skip.
    pub start: u32,
    /// Page size; the service clamps it.
    pub limit: Option<u32>,
}

/// A message the server sent, as held by the mail capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedMail {
    /// The capture's message id.
    pub id: String,
    /// Sender address.
    pub from: String,
    /// Recipient addresses.
    pub to: Vec<String>,
    /// Subject line.
    pub subject: String,
    /// When the message was captured.
    pub created_at: DateTime<Utc>,
    /// The start of the plain-text body.
    pub snippet: String,
}

/// One page of captured messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailPage {
    /// The messages, newest first.
    pub messages: Vec<CapturedMail>,
    /// How many messages match in total.
    pub total: u32,
}

/// A captured message with its bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedMessage {
    /// The message's summary.
    pub mail: CapturedMail,
    /// Plain-text body, if any.
    pub text: Option<String>,
    /// HTML body, if any. Untrusted: render it sandboxed.
    pub html: Option<String>,
}

/// An administrative action recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    /// The first account became root admin (taken by the system).
    RootClaimed,
    /// An account was made admin.
    AdminGranted,
    /// An account stopped being admin.
    AdminRevoked,
    /// An account was disabled.
    UserDisabled,
    /// A disabled account was enabled again.
    UserEnabled,
    /// The signup policy changed.
    SignupPolicyChanged,
    /// An email was allowed to sign up.
    AllowedEmailAdded,
    /// An email was removed from the signup allowlist.
    AllowedEmailRemoved,
    /// An allowed email was sent an invitation to join this server.
    AllowedEmailInvited,
    /// A workspace's invite link was turned off.
    InviteLinkRevoked,
    /// A pending workspace email invite was cancelled.
    TeamInviteRevoked,
    /// A pending workspace email invite was emailed again.
    TeamInviteResent,
    /// A captured outgoing message was deleted.
    CapturedMailDeleted,
    /// Every captured outgoing message was deleted.
    CapturedMailCleared,
}

impl AuditAction {
    /// Every action, in the order the admin panel lists them.
    pub const ALL: [Self; 14] = [
        Self::RootClaimed,
        Self::AdminGranted,
        Self::AdminRevoked,
        Self::UserDisabled,
        Self::UserEnabled,
        Self::SignupPolicyChanged,
        Self::AllowedEmailAdded,
        Self::AllowedEmailRemoved,
        Self::AllowedEmailInvited,
        Self::InviteLinkRevoked,
        Self::TeamInviteRevoked,
        Self::TeamInviteResent,
        Self::CapturedMailDeleted,
        Self::CapturedMailCleared,
    ];

    /// The stored and API string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootClaimed => "root_claimed",
            Self::AdminGranted => "admin_granted",
            Self::AdminRevoked => "admin_revoked",
            Self::UserDisabled => "user_disabled",
            Self::UserEnabled => "user_enabled",
            Self::SignupPolicyChanged => "signup_policy_changed",
            Self::AllowedEmailAdded => "allowed_email_added",
            Self::AllowedEmailRemoved => "allowed_email_removed",
            Self::AllowedEmailInvited => "allowed_email_invited",
            Self::InviteLinkRevoked => "invite_link_revoked",
            Self::TeamInviteRevoked => "team_invite_revoked",
            Self::TeamInviteResent => "team_invite_resent",
            Self::CapturedMailDeleted => "captured_mail_deleted",
            Self::CapturedMailCleared => "captured_mail_cleared",
        }
    }

    /// Parses the stored or API string form.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.as_str() == s)
    }
}

/// Where an audited action stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditStatus {
    /// Recorded before running; still pending when the outcome could not be stored.
    Pending,
    /// The action took effect.
    Succeeded,
    /// The action was refused or failed, with the reason.
    Failed(String),
}

/// An action about to run, as recorded before it runs.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAuditEntry {
    /// Macro user id of the admin; `None` for the system.
    pub actor: Option<String>,
    /// What is being done.
    pub action: AuditAction,
    /// What it applies to: a profile id or an email.
    pub target: Option<String>,
    /// Action-specific values, such as the new policy.
    pub details: serde_json::Value,
}

/// A recorded action.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    /// Increasing id; also the paging cursor.
    pub id: i64,
    /// When the action was recorded.
    pub created_at: DateTime<Utc>,
    /// The recorded action.
    pub entry: NewAuditEntry,
    /// Its outcome.
    pub status: AuditStatus,
    /// When the outcome was recorded.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Which audit entries to list, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Only this action.
    pub action: Option<AuditAction>,
    /// Only entries whose actor or target contains this text, case-insensitively.
    pub search: Option<String>,
    /// Only entries older than this id (the previous page's last id).
    pub before: Option<i64>,
    /// Page size; the service clamps it.
    pub limit: Option<i64>,
}

/// Errors from self-host operations. Each variant maps to one HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum SelfHostError {
    /// The request is malformed (400).
    #[error("{0}")]
    Invalid(String),
    /// The caller is not an admin (403).
    #[error("admin role required")]
    Forbidden,
    /// The target does not exist (404); names what was looked for.
    #[error("{0} not found")]
    NotFound(&'static str),
    /// The request breaks a self-host rule (409).
    #[error("{0}")]
    Conflict(String),
    /// A service this needs is not set up or not reachable (503).
    #[error("{0}")]
    Unavailable(String),
    /// An infrastructure failure (500).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
