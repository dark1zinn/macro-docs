//! Postgres adapter for [`AuditLog`](crate::domain::ports::AuditLog).
//!
//! The table's trigger keeps it append-only: rows are never deleted, and only a
//! pending row may change, once, to its outcome.

use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::domain::model::{AuditAction, AuditEntry, AuditQuery, AuditStatus, NewAuditEntry};
use crate::domain::ports::AuditLog;

#[cfg(test)]
mod test;

/// Postgres-backed audit log over the MacroDB pool.
#[derive(Clone)]
pub struct PgAuditLog {
    pool: PgPool,
}

impl PgAuditLog {
    /// Creates the audit log over `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Escapes `ILIKE` wildcards so the search text matches literally.
fn like_pattern(search: &str) -> String {
    let escaped = search
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// The stored status and error of entry `id` as an [`AuditStatus`].
fn parse_status(id: i64, status: &str, error: Option<String>) -> anyhow::Result<AuditStatus> {
    Ok(match status {
        "pending" => AuditStatus::Pending,
        "succeeded" => AuditStatus::Succeeded,
        "failed" => AuditStatus::Failed(error.unwrap_or_default()),
        other => anyhow::bail!("unknown audit status {other:?} in entry {id}"),
    })
}

#[async_trait]
impl AuditLog for PgAuditLog {
    async fn begin(&self, entry: &NewAuditEntry) -> anyhow::Result<i64> {
        let id = sqlx::query_scalar!(
            r#"INSERT INTO selfhost_audit_log (actor, action, target, details)
               VALUES ($1, $2, $3, $4) RETURNING id"#,
            entry.actor.as_deref(),
            entry.action.as_str(),
            entry.target.as_deref(),
            &entry.details,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    async fn finish(&self, id: i64, status: &AuditStatus) -> anyhow::Result<()> {
        let (status, error) = match status {
            AuditStatus::Pending => anyhow::bail!("an audit entry cannot finish as pending"),
            AuditStatus::Succeeded => ("succeeded", None),
            AuditStatus::Failed(error) => ("failed", Some(error.as_str())),
        };
        let settled = sqlx::query!(
            r#"UPDATE selfhost_audit_log
               SET status = $2, error = $3, completed_at = now()
               WHERE id = $1 AND status = 'pending'"#,
            id,
            status,
            error,
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        anyhow::ensure!(settled == 1, "audit entry {id} is not pending");
        Ok(())
    }

    async fn list(&self, query: &AuditQuery) -> anyhow::Result<Vec<AuditEntry>> {
        let rows = sqlx::query!(
            r#"SELECT id, created_at, actor, action, target, details, status, error, completed_at
               FROM selfhost_audit_log
               WHERE ($1::text IS NULL OR action = $1)
                 AND ($2::text IS NULL OR actor ILIKE $2 OR target ILIKE $2)
                 AND ($3::bigint IS NULL OR id < $3)
               ORDER BY id DESC
               LIMIT $4"#,
            query.action.map(AuditAction::as_str),
            query.search.as_deref().map(like_pattern),
            query.before,
            query.limit,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let action = AuditAction::parse(&row.action).with_context(|| {
                    format!("unknown audit action {:?} in entry {}", row.action, row.id)
                })?;
                Ok(AuditEntry {
                    id: row.id,
                    created_at: row.created_at,
                    status: parse_status(row.id, &row.status, row.error)?,
                    completed_at: row.completed_at,
                    entry: NewAuditEntry {
                        actor: row.actor,
                        action,
                        target: row.target,
                        details: row.details,
                    },
                })
            })
            .collect()
    }
}
