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
