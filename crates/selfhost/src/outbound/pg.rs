//! Postgres adapter for [`SelfHostRepo`](crate::domain::ports::SelfHostRepo).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use macro_user_id::user_id::MacroUserIdStr;
use sqlx::{PgPool, Postgres, Transaction};

use crate::domain::model::{AllowedEmail, SignupPolicy, UserRecord};
use crate::domain::ports::SelfHostRepo;

/// Postgres-backed self-host repository over the MacroDB pool.
#[derive(Clone)]
pub struct PgSelfHostRepo {
    pool: PgPool,
}

impl PgSelfHostRepo {
    /// Creates the repository over `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Takes the transaction-scoped lock that serializes every root and admin
/// state change. It is released at commit or rollback.
async fn lock_admin_state(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    sqlx::query!(
        "SELECT 1 AS \"locked!\" FROM (SELECT pg_advisory_xact_lock(hashtext('selfhost_root_claim'))) AS root_claim_lock"
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(())
}

fn to_record(
    user_id: String,
    email: String,
    fusionauth_user_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
    is_admin: bool,
    disabled: bool,
) -> anyhow::Result<UserRecord> {
    let macro_user_id = MacroUserIdStr::try_from_email(&email)
        .map_err(|e| anyhow::anyhow!("invalid stored email for macro id: {e}"))?
        .to_string();
    Ok(UserRecord {
        user_id,
        email,
        macro_user_id,
        fusionauth_user_id,
        created_at,
        is_admin,
        disabled,
    })
}

#[async_trait]
impl SelfHostRepo for PgSelfHostRepo {
    async fn root_exists(&self) -> anyhow::Result<bool> {
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM "RolesOnUsers" WHERE "roleId" = 'super_admin') AS "exists!""#
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    async fn claim_root_admin(&self, macro_user_id: &str) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        // Serializes concurrent first signups so exactly one account becomes root.
        lock_admin_state(&mut tx).await?;
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM "RolesOnUsers" WHERE "roleId" = 'super_admin') AS "exists!""#
        )
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            return Ok(false);
        }
        sqlx::query!(
            r#"INSERT INTO "RolesOnUsers" ("userId", "roleId") VALUES ($1, 'super_admin') ON CONFLICT DO NOTHING"#,
            macro_user_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn revoke_admin_unless_last(&self, macro_user_id: &str) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        lock_admin_state(&mut tx).await?;
        // Active admins hold super_admin, have a profile, and are not disabled.
        // The revoke is allowed when the target is not an active admin, or when
        // another active admin remains.
        let result = sqlx::query!(
            r#"WITH active AS (
                   SELECT r."userId" AS macro_id
                   FROM "RolesOnUsers" r
                   JOIN "User" u ON r."userId" = 'macro|' || u.email
                   WHERE r."roleId" = 'super_admin'
                     AND NOT EXISTS (SELECT 1 FROM selfhost_disabled_user d WHERE d.user_id = u.id)
               )
               DELETE FROM "RolesOnUsers"
               WHERE "userId" = $1 AND "roleId" = 'super_admin'
                 AND (NOT EXISTS (SELECT 1 FROM active WHERE macro_id = $1)
                      OR EXISTS (SELECT 1 FROM active WHERE macro_id <> $1))"#,
            macro_user_id
        )
        .execute(&mut *tx)
        .await?;
        let revoked = result.rows_affected() > 0;
        if revoked {
            tx.commit().await?;
        }
        Ok(revoked)
    }

    async fn mark_disabled_unless_last_admin(
        &self,
        user_id: &str,
        by: &str,
    ) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        lock_admin_state(&mut tx).await?;
        // Same rule as revoke: the marker is refused only when it would disable
        // the sole remaining active admin.
        let result = sqlx::query!(
            r#"WITH active AS (
                   SELECT u.id AS user_id
                   FROM "RolesOnUsers" r
                   JOIN "User" u ON r."userId" = 'macro|' || u.email
                   WHERE r."roleId" = 'super_admin'
                     AND NOT EXISTS (SELECT 1 FROM selfhost_disabled_user d WHERE d.user_id = u.id)
               )
               INSERT INTO selfhost_disabled_user (user_id, disabled_by)
               SELECT $1::text, $2::text
               WHERE EXISTS (SELECT 1 FROM "User" WHERE id = $1)
                 AND (NOT EXISTS (SELECT 1 FROM active WHERE user_id = $1)
                      OR EXISTS (SELECT 1 FROM active WHERE user_id <> $1))
               ON CONFLICT (user_id) DO UPDATE
               SET disabled_by = EXCLUDED.disabled_by, disabled_at = now()"#,
            user_id,
            by
        )
        .execute(&mut *tx)
        .await?;
        let marked = result.rows_affected() > 0;
        if marked {
            tx.commit().await?;
        }
        Ok(marked)
    }

    async fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let rows = sqlx::query!(
            r#"SELECT u.id AS "user_id!", u.email AS "email!", u."createdAt" AS "created_at?",
                u.macro_user_id::text AS "fusionauth_user_id?",
                EXISTS(SELECT 1 FROM "RolesOnUsers" r
                       WHERE r."userId" = 'macro|' || u.email AND r."roleId" = 'super_admin') AS "is_admin!",
                EXISTS(SELECT 1 FROM selfhost_disabled_user d WHERE d.user_id = u.id) AS "disabled!"
               FROM "User" u
               ORDER BY u."createdAt" ASC NULLS FIRST, u.id ASC"#
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                to_record(
                    r.user_id,
                    r.email,
                    r.fusionauth_user_id,
                    r.created_at,
                    r.is_admin,
                    r.disabled,
                )
            })
            .collect()
    }

    async fn find_user(&self, user_id: &str) -> anyhow::Result<Option<UserRecord>> {
        let row = sqlx::query!(
            r#"SELECT u.id AS "user_id!", u.email AS "email!", u."createdAt" AS "created_at?",
                u.macro_user_id::text AS "fusionauth_user_id?",
                EXISTS(SELECT 1 FROM "RolesOnUsers" r
                       WHERE r."userId" = 'macro|' || u.email AND r."roleId" = 'super_admin') AS "is_admin!",
                EXISTS(SELECT 1 FROM selfhost_disabled_user d WHERE d.user_id = u.id) AS "disabled!"
               FROM "User" u
               WHERE u.id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            to_record(
                r.user_id,
                r.email,
                r.fusionauth_user_id,
                r.created_at,
                r.is_admin,
                r.disabled,
            )
        })
        .transpose()
    }

    async fn set_disabled(&self, user_id: &str, disabled: bool, by: &str) -> anyhow::Result<()> {
        if disabled {
            sqlx::query!(
                r#"INSERT INTO selfhost_disabled_user (user_id, disabled_by) VALUES ($1, $2)
                   ON CONFLICT (user_id) DO UPDATE SET disabled_by = EXCLUDED.disabled_by, disabled_at = now()"#,
                user_id,
                by
            )
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query!(
                "DELETE FROM selfhost_disabled_user WHERE user_id = $1",
                user_id
            )
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn get_policy(&self) -> anyhow::Result<SignupPolicy> {
        let raw = sqlx::query_scalar!("SELECT signup_policy FROM selfhost_settings WHERE id")
            .fetch_optional(&self.pool)
            .await?;
        match raw {
            None => Ok(SignupPolicy::InviteOnly),
            Some(s) => SignupPolicy::parse(&s)
                .ok_or_else(|| anyhow::anyhow!("unknown signup policy stored in database")),
        }
    }

    async fn set_policy(&self, policy: SignupPolicy, by: &str) -> anyhow::Result<()> {
        sqlx::query!(
            r#"INSERT INTO selfhost_settings (id, signup_policy, updated_by) VALUES (TRUE, $1, $2)
               ON CONFLICT (id) DO UPDATE
               SET signup_policy = EXCLUDED.signup_policy, updated_at = now(), updated_by = EXCLUDED.updated_by"#,
            policy.as_str(),
            by
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_allowed_emails(&self) -> anyhow::Result<Vec<AllowedEmail>> {
        let rows = sqlx::query!(
            r#"SELECT email AS "email!", created_at AS "created_at!"
               FROM selfhost_signup_allowlist
               ORDER BY created_at ASC, email ASC"#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AllowedEmail {
                email: r.email,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn add_allowed_email(&self, email: &str, by: &str) -> anyhow::Result<()> {
        sqlx::query!(
            "INSERT INTO selfhost_signup_allowlist (email, added_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
            email,
            by
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_allowed_email(&self, email: &str) -> anyhow::Result<()> {
        sqlx::query!(
            "DELETE FROM selfhost_signup_allowlist WHERE email = $1",
            email
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn has_signup_grant(&self, email: &str) -> anyhow::Result<bool> {
        let granted = sqlx::query_scalar!(
            r#"SELECT (EXISTS(SELECT 1 FROM selfhost_signup_allowlist WHERE email = $1)
                       OR EXISTS(SELECT 1 FROM team_invite WHERE email = $1)) AS "granted!""#,
            email
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(granted)
    }
}

#[cfg(test)]
mod test;
