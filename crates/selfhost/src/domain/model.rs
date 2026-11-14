//! Plain data types for self-host administration.

use chrono::{DateTime, Utc};

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
}

impl AuditAction {
    /// Every action, in the order the admin panel lists them.
    pub const ALL: [Self; 8] = [
        Self::RootClaimed,
        Self::AdminGranted,
        Self::AdminRevoked,
        Self::UserDisabled,
        Self::UserEnabled,
        Self::SignupPolicyChanged,
        Self::AllowedEmailAdded,
        Self::AllowedEmailRemoved,
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
    /// The target does not exist (404).
    #[error("user not found")]
    NotFound,
    /// The request breaks a self-host rule (409).
    #[error("{0}")]
    Conflict(String),
    /// An infrastructure failure (500).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
