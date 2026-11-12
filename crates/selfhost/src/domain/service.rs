//! Self-host rules: entitlements, root admin, signup policy, and admin actions.

use macro_user_id::user_id::MacroUserIdStr;
use roles_and_permissions::domain::model::RoleId;

use super::model::{AllowedEmail, SelfHostError, SignupPolicy, UserEntry, UserRecord};
use super::ports::{AccountPort, RolesPort, SelfHostRepo};

/// Roles granted to every account so self-host users are fully entitled.
fn entitlements() -> [RoleId; 2] {
    [RoleId::ProfessionalSubscriber, RoleId::SubMax]
}

/// Enforces self-host rules over the ports.
pub struct SelfHostService<R, P, A> {
    repo: R,
    roles: P,
    accounts: A,
}

impl<R, P, A> SelfHostService<R, P, A>
where
    R: SelfHostRepo,
    P: RolesPort,
    A: AccountPort,
{
    /// Creates the service from its ports.
    pub fn new(repo: R, roles: P, accounts: A) -> Self {
        Self {
            repo,
            roles,
            accounts,
        }
    }

    /// Applies entitlements to a newly created account and claims root if none exists.
    pub async fn on_user_created(&self, email: &str) -> Result<(), SelfHostError> {
        let macro_user_id = macro_user_id_for(email)?;
        self.roles
            .grant_roles(&macro_user_id, &entitlements())
            .await?;
        if self.repo.claim_root_admin(&macro_user_id).await? {
            tracing::info!("selfhost root admin claimed");
        }
        Ok(())
    }

    /// Re-applies entitlements to every existing account, oldest first, so the
    /// oldest account becomes root when no admin exists. Idempotent.
    pub async fn backfill(&self) -> Result<(), SelfHostError> {
        for record in self.repo.list_users().await? {
            self.on_user_created(&record.email).await?;
        }
        Ok(())
    }

    /// Decides whether a signup with `email` may proceed.
    ///
    /// Signup is always open until a root admin exists. After that, `Open`
    /// allows everyone, and `InviteOnly` allows allowlisted or invited emails.
    pub async fn authorize_signup(&self, email: &str) -> Result<bool, SelfHostError> {
        let Ok(email) = normalize_email(email) else {
            return Ok(false);
        };
        if !self.repo.root_exists().await? {
            return Ok(true);
        }
        match self.repo.get_policy().await? {
            SignupPolicy::Open => Ok(true),
            SignupPolicy::InviteOnly => Ok(self.repo.has_signup_grant(&email).await?),
        }
    }

    /// Lists every account. Requires an admin caller.
    pub async fn list_users(&self, caller: &str) -> Result<Vec<UserEntry>, SelfHostError> {
        self.require_admin(caller).await?;
        Ok(self
            .repo
            .list_users()
            .await?
            .into_iter()
            .map(|record| {
                let is_self = record.macro_user_id == caller;
                UserEntry { record, is_self }
            })
            .collect())
    }

    /// Grants or revokes the super admin role. Requires an admin caller.
    pub async fn set_admin(
        &self,
        caller: &str,
        user_id: &str,
        admin: bool,
    ) -> Result<(), SelfHostError> {
        self.require_admin(caller).await?;
        let target = self.target(user_id).await?;
        if target.is_admin == admin {
            return Ok(());
        }
        if admin {
            self.roles
                .grant_roles(&target.macro_user_id, &[RoleId::SuperAdmin])
                .await?;
        } else if !self
            .repo
            .revoke_admin_unless_last(&target.macro_user_id)
            .await?
        {
            return Err(SelfHostError::Conflict(
                "cannot demote the last active admin".into(),
            ));
        }
        Ok(())
    }

    /// Disables or re-enables an account. Requires an admin caller.
    ///
    /// Disabling records the marker first; the repo refuses it for the last active
    /// admin. The identity is then deactivated. If deactivation fails, the marker
    /// is removed again so the local and identity states agree.
    pub async fn set_disabled(
        &self,
        caller: &str,
        user_id: &str,
        disabled: bool,
    ) -> Result<(), SelfHostError> {
        self.require_admin(caller).await?;
        let target = self.target(user_id).await?;
        if disabled && target.macro_user_id == caller {
            return Err(SelfHostError::Conflict(
                "cannot disable your own account".into(),
            ));
        }
        if target.disabled == disabled {
            return Ok(());
        }
        let fusionauth_id = target
            .fusionauth_user_id
            .as_deref()
            .ok_or_else(|| SelfHostError::Conflict("account has no identity provider id".into()))?;
        if disabled {
            if !self
                .repo
                .mark_disabled_unless_last_admin(&target.user_id, caller)
                .await?
            {
                return Err(SelfHostError::Conflict(
                    "cannot disable the last active admin".into(),
                ));
            }
            if let Err(err) = self.accounts.set_active(fusionauth_id, false).await {
                if let Err(undo) = self.repo.set_disabled(&target.user_id, false, caller).await {
                    tracing::error!(error = ?undo, "failed to undo disable marker");
                }
                return Err(err.into());
            }
        } else {
            self.accounts.set_active(fusionauth_id, true).await?;
            self.repo
                .set_disabled(&target.user_id, false, caller)
                .await?;
        }
        Ok(())
    }

    /// Returns the signup policy and allowed emails. Requires an admin caller.
    pub async fn get_signups(
        &self,
        caller: &str,
    ) -> Result<(SignupPolicy, Vec<AllowedEmail>), SelfHostError> {
        self.require_admin(caller).await?;
        Ok((
            self.repo.get_policy().await?,
            self.repo.list_allowed_emails().await?,
        ))
    }

    /// Sets the signup policy. Requires an admin caller.
    pub async fn set_policy(
        &self,
        caller: &str,
        policy: SignupPolicy,
    ) -> Result<(), SelfHostError> {
        self.require_admin(caller).await?;
        self.repo.set_policy(policy, caller).await?;
        Ok(())
    }

    /// Allowlists a signup email. Requires an admin caller.
    pub async fn add_allowed_email(&self, caller: &str, email: &str) -> Result<(), SelfHostError> {
        self.require_admin(caller).await?;
        let email = normalize_email(email)?;
        self.repo.add_allowed_email(&email, caller).await?;
        Ok(())
    }

    /// Removes a signup email from the allowlist. Requires an admin caller.
    pub async fn remove_allowed_email(
        &self,
        caller: &str,
        email: &str,
    ) -> Result<(), SelfHostError> {
        self.require_admin(caller).await?;
        let email = normalize_email(email)?;
        self.repo.remove_allowed_email(&email).await?;
        Ok(())
    }

    async fn require_admin(&self, caller: &str) -> Result<(), SelfHostError> {
        if self
            .roles
            .get_roles(caller)
            .await?
            .contains(&RoleId::SuperAdmin)
        {
            Ok(())
        } else {
            Err(SelfHostError::Forbidden)
        }
    }

    async fn target(&self, user_id: &str) -> Result<UserRecord, SelfHostError> {
        self.repo
            .find_user(user_id)
            .await?
            .ok_or(SelfHostError::NotFound)
    }
}

fn macro_user_id_for(email: &str) -> Result<String, SelfHostError> {
    MacroUserIdStr::try_from_email(email)
        .map(|id| id.to_string())
        .map_err(|e| SelfHostError::Internal(anyhow::anyhow!("invalid email for macro id: {e}")))
}

/// Trims and lowercases an email, rejecting anything that is not a plausible address.
pub fn normalize_email(raw: &str) -> Result<String, SelfHostError> {
    let email = raw.trim().to_lowercase();
    if email.contains('@') && !email.contains(char::is_whitespace) && email.len() <= 320 {
        Ok(email)
    } else {
        Err(SelfHostError::Invalid("invalid email address".into()))
    }
}
