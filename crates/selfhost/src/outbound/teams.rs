//! [`WorkspaceInvites`] over MacroDB and the teams service.
//!
//! Reads list every workspace's links and invites straight from MacroDB.
//! Changes go through the teams service so its rules, events and emails apply:
//! the self-host domain has already confirmed the caller is an instance admin,
//! and this adapter turns that into the workspace access receipt the teams
//! service expects, naming the admin as the actor.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use entity_access::domain::models::{
    AdminTeamRole, Entity, EntityAccessReceipt, EntityPermission, MemberTeamRole,
    RequiredPermission, TeamRole,
};
use macro_user_id::cowlike::CowLike;
use macro_user_id::email::Email;
use macro_user_id::user_id::MacroUserIdStr;
use model_entity::EntityType;
use sqlx::PgPool;
use teams::domain::model::{InviteUsersToTeamError, TeamError};
use teams::domain::team_repo::{TeamInviteLinkService, TeamService};
use teams::domain::team_service::invite_resend::ImmediateInviteResender;
use teams::domain::team_service::invite_resend_interval;
use uuid::Uuid;

use crate::domain::model::{InviteLinkRecord, PendingInvite, SelfHostError};
use crate::domain::ports::WorkspaceInvites;

/// Workspace invites over MacroDB and the teams service `T`.
pub struct TeamsInvites<T> {
    pool: PgPool,
    teams: Arc<T>,
}

impl<T> TeamsInvites<T> {
    /// Creates the adapter.
    pub fn new(pool: PgPool, teams: Arc<T>) -> Self {
        Self { pool, teams }
    }
}

/// A workspace receipt for `admin` with the workspace admin role.
fn admin_receipt<R: RequiredPermission>(
    admin: &str,
    team_id: Uuid,
) -> Result<EntityAccessReceipt<R>, SelfHostError> {
    let user = MacroUserIdStr::parse_from_str(admin)
        .map_err(|e| anyhow::anyhow!("invalid admin id: {e:?}"))?
        .into_owned();
    EntityAccessReceipt::try_new_authenticated_user(
        user,
        Entity {
            entity_id: team_id.to_string(),
            entity_type: EntityType::Team,
        },
        EntityPermission::TeamRole {
            role: TeamRole::Admin,
        },
    )
    .map_err(|e| SelfHostError::Internal(anyhow::anyhow!("workspace receipt: {e:?}")))
}

/// A `team_invite` row with its workspace name.
struct PendingRow {
    id: Uuid,
    team_id: Uuid,
    team_name: String,
    email: String,
    invited_by: String,
    is_agent: bool,
    created_at: NaiveDateTime,
    last_sent_at: NaiveDateTime,
}

impl From<PendingRow> for PendingInvite {
    fn from(row: PendingRow) -> Self {
        // `team_invite` stores UTC without a zone.
        let last_sent_at: DateTime<Utc> = row.last_sent_at.and_utc();
        let resend_after = chrono::Duration::from_std(invite_resend_interval())
            .unwrap_or_else(|_| chrono::Duration::zero());
        Self {
            invite_id: row.id,
            team_id: row.team_id,
            team_name: row.team_name,
            email: row.email,
            invited_by: row.invited_by,
            is_agent: row.is_agent,
            created_at: row.created_at.and_utc(),
            last_sent_at,
            resendable_at: last_sent_at + resend_after,
        }
    }
}

/// A `team_invite_link` row with its workspace name.
struct LinkRow {
    team_id: Uuid,
    team_name: String,
    token: Uuid,
    created_at: DateTime<Utc>,
    created_by: Option<String>,
}

impl From<LinkRow> for InviteLinkRecord {
    fn from(row: LinkRow) -> Self {
        Self {
            team_id: row.team_id,
            team_name: row.team_name,
            token: row.token,
            created_at: row.created_at,
            created_by: row.created_by,
        }
    }
}

#[async_trait]
impl<T> WorkspaceInvites for TeamsInvites<T>
where
    T: TeamService + TeamInviteLinkService + ImmediateInviteResender,
{
    async fn list_links(&self) -> anyhow::Result<Vec<InviteLinkRecord>> {
        let rows = sqlx::query_as!(
            LinkRow,
            r#"SELECT l.team_id, t.name AS team_name, l.token, l.created_at, l.created_by
               FROM team_invite_link l JOIN team t ON t.id = l.team_id
               ORDER BY l.created_at DESC"#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_pending(&self) -> anyhow::Result<Vec<PendingInvite>> {
        let rows = sqlx::query_as!(
            PendingRow,
            r#"SELECT i.id, i.team_id, t.name AS team_name, i.email, i.invited_by, i.is_agent,
                      i.created_at, i.last_sent_at
               FROM team_invite i JOIN team t ON t.id = i.team_id
               ORDER BY i.created_at DESC"#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn find_link(&self, team_id: Uuid) -> anyhow::Result<Option<InviteLinkRecord>> {
        let row = sqlx::query_as!(
            LinkRow,
            r#"SELECT l.team_id, t.name AS team_name, l.token, l.created_at, l.created_by
               FROM team_invite_link l JOIN team t ON t.id = l.team_id
               WHERE l.team_id = $1"#,
            team_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_pending(&self, invite_id: Uuid) -> anyhow::Result<Option<PendingInvite>> {
        let row = sqlx::query_as!(
            PendingRow,
            r#"SELECT i.id, i.team_id, t.name AS team_name, i.email, i.invited_by, i.is_agent,
                      i.created_at, i.last_sent_at
               FROM team_invite i JOIN team t ON t.id = i.team_id
               WHERE i.id = $1"#,
            invite_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn revoke_link(&self, admin: &str, team_id: Uuid) -> Result<(), SelfHostError> {
        let receipt = admin_receipt::<AdminTeamRole>(admin, team_id)?;
        self.teams
            .delete_team_invite_link(receipt)
            .await
            .map_err(|e| SelfHostError::Internal(anyhow::anyhow!("turning off invite link: {e}")))
    }

    async fn revoke_invite(
        &self,
        admin: &str,
        invite: &PendingInvite,
    ) -> Result<(), SelfHostError> {
        let receipt = admin_receipt::<AdminTeamRole>(admin, invite.team_id)?;
        self.teams
            .delete_team_invite(receipt, &invite.invite_id)
            .await
            .map_err(|e| SelfHostError::Internal(anyhow::anyhow!("cancelling invite: {e}")))
    }

    async fn resend_invite(
        &self,
        admin: &str,
        invite: &PendingInvite,
        now: bool,
    ) -> Result<bool, SelfHostError> {
        let sent = if now {
            let receipt = admin_receipt::<AdminTeamRole>(admin, invite.team_id)?;
            self.teams
                .resend_invite_now(receipt, invite.invite_id)
                .await
                .map(|()| true)
        } else {
            let receipt = admin_receipt::<MemberTeamRole>(admin, invite.team_id)?;
            let email = Email::parse_from_str(&invite.email)
                .map_err(|e| anyhow::anyhow!("invalid stored invite email: {e}"))?
                .lowercase();
            let emails = [email];
            let emails = non_empty::NonEmpty::new(&emails[..])
                .map_err(|_| anyhow::anyhow!("no address to invite"))?;
            // Inviting an address that already has a pending invite emails it
            // again, unless it was emailed inside the resend window.
            self.teams
                .invite_users_to_team(receipt, emails, invite.is_agent)
                .await
                .map(|sent| !sent.is_empty())
        };
        match sent {
            Ok(sent) => Ok(sent),
            Err(InviteUsersToTeamError::TeamError(TeamError::TeamInviteDoesNotExist)) => {
                Err(SelfHostError::NotFound("invite"))
            }
            Err(InviteUsersToTeamError::NonAdminInvitesDisabled) => Err(SelfHostError::Conflict(
                "this workspace only lets its own admins send invites; ask one of them to resend it"
                    .into(),
            )),
            Err(InviteUsersToTeamError::TooManyEmails) => Err(SelfHostError::Conflict(
                "this workspace has sent too many invites today; try again tomorrow".into(),
            )),
            Err(e) => Err(SelfHostError::Internal(anyhow::anyhow!(
                "resending invite: {e}"
            ))),
        }
    }
}
