//! [`ServerInviter`] over the notification service's self-host invitation
//! email ([`ServerInvite`]), which links to sign-up on this server with no
//! referral code.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use invite_email::ServerInvite;
use macro_user_id::cowlike::CowLike;
use macro_user_id::email::EmailStr;
use macro_user_id::user_id::MacroUserIdStr;
use model_entity::EntityType;
use notification::domain::models::SendNotificationRequestBuilder;
use notification::domain::service::NotificationIngress;
use sqlx::PgPool;

use crate::domain::ports::ServerInviter;

/// Sends server invitations through the notification service `N`, naming the
/// admin from their profile in MacroDB.
pub struct NotificationInviter<N> {
    pool: PgPool,
    notifications: Arc<N>,
}

impl<N> NotificationInviter<N> {
    /// Creates the adapter.
    pub fn new(pool: PgPool, notifications: Arc<N>) -> Self {
        Self {
            pool,
            notifications,
        }
    }

    /// The admin's display name. The email falls back to their address, so a
    /// failed lookup is logged rather than failing the invitation.
    async fn display_name(&self, admin: &str) -> Option<String> {
        sqlx::query_scalar!(
            r#"SELECT NULLIF(TRIM(CONCAT_WS(' ', NULLIF(mui.first_name, 'N/A'),
                                               NULLIF(mui.last_name, 'N/A'))), '') AS "name?: String"
               FROM macro_user_info mui
               JOIN "User" u ON u.macro_user_id = mui.macro_user_id
               WHERE u.id = $1"#,
            admin
        )
        .fetch_optional(&self.pool)
        .await
        .inspect_err(|e| tracing::warn!(error = ?e, "unable to look up the admin's name"))
        .ok()
        .flatten()
        .flatten()
    }
}

#[async_trait]
impl<N: NotificationIngress> ServerInviter for NotificationInviter<N> {
    fn resend_interval(&self) -> std::time::Duration {
        ServerInvite::RESEND_INTERVAL
    }

    async fn invite(&self, admin: &str, email: &str) -> anyhow::Result<()> {
        let invited_by = MacroUserIdStr::parse_from_str(admin)
            .map_err(|e| anyhow::anyhow!("invalid admin id: {e:?}"))?
            .into_owned();
        let recipient_email = EmailStr::try_from(email.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid invite email: {e:?}"))?;
        let recipient = MacroUserIdStr::try_from_email(email)
            .map_err(|e| anyhow::anyhow!("invalid invite email: {e:?}"))?
            .into_owned();
        let request = SendNotificationRequestBuilder {
            notification_entity: EntityType::User.with_entity_string(admin.to_owned()),
            secondary_notification_entity: None,
            sender_id: Some(invited_by.clone()),
            notification: ServerInvite {
                recipient_email,
                invited_by,
                inviter_name: self.display_name(admin).await,
            },
            recipient_ids: HashSet::from([recipient]),
        }
        .into_request()
        .with_email();
        self.notifications
            .send_notification(request)
            .await
            .map_err(|e| anyhow::anyhow!("sending server invite: {e}"))?;
        Ok(())
    }
}
