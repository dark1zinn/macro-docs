//! Emailing a pending team invite again right away, inside the window that
//! normally holds resends back. For an operator who has confirmed the
//! address; ordinary resends go through `invite_users_to_team`.

use std::collections::HashSet;

use channels::domain::ports::ChannelService;
use entity_access::domain::models::{AdminTeamRole, EntityAccessReceipt};
use macro_event_broker::MacroEventBroker;
use macro_user_id::{cowlike::CowLike, user_id::MacroUserIdStr};
use model_entity::EntityType;
use model_notifications::{InviteToTeamMetadata, InviteePlan};
use notification::domain::{models::SendNotificationRequestBuilder, service::NotificationIngress};
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;

use super::TeamServiceImpl;
use crate::domain::{
    contacts_enqueuer::ContactsEnqueuer,
    crm_enqueuer::CrmEnqueuer,
    customer_repo::CustomerRepository,
    model::{InviteUsersToTeamError, TeamError, TeamRole},
    open_seat_release::OpenSeatRelease,
    owned_entity_cleanup::OwnedEntityCleanup,
    team_analytics::TeamAnalytics,
    team_crm_settings_repo::TeamCrmSettingsRepository,
    team_repo::TeamRepository,
};

/// Emails a pending invite again without waiting for its resend window.
pub trait ImmediateInviteResender: Send + Sync + 'static {
    /// Emails the invite `invite_id` of the receipt's team now, as the
    /// receipt's user. The team's rule that only its admins may invite still
    /// applies to that user's own role in the team.
    fn resend_invite_now(
        &self,
        receipt: EntityAccessReceipt<AdminTeamRole>,
        invite_id: uuid::Uuid,
    ) -> impl Future<Output = Result<(), InviteUsersToTeamError>> + Send;
}

impl<TR, CR, CS, URPS, NI, CE, TCRMS, TA, CNE, EB, OSR, OEC> ImmediateInviteResender
    for TeamServiceImpl<TR, CR, CS, URPS, NI, CE, TCRMS, TA, CNE, EB, OSR, OEC>
where
    TR: TeamRepository,
    CR: CustomerRepository,
    CS: ChannelService + Clone,
    URPS: UserRolesAndPermissionsService,
    NI: NotificationIngress,
    CE: CrmEnqueuer,
    TCRMS: TeamCrmSettingsRepository,
    TA: TeamAnalytics,
    CNE: ContactsEnqueuer,
    EB: MacroEventBroker,
    OSR: OpenSeatRelease,
    OEC: OwnedEntityCleanup,
{
    #[tracing::instrument(
        name = "teams.resend_invite_now",
        skip(self, receipt),
        fields(team_id = %receipt.entity().entity_id, team_invite_id = %invite_id),
        err
    )]
    async fn resend_invite_now(
        &self,
        receipt: EntityAccessReceipt<AdminTeamRole>,
        invite_id: uuid::Uuid,
    ) -> Result<(), InviteUsersToTeamError> {
        let team_id = macro_uuid::string_to_uuid(&receipt.entity().entity_id)
            .map_err(|e| anyhow::anyhow!("invalid team id: {e}"))?;
        let invite = self
            .team_repository
            .get_team_invite_by_id(&invite_id)
            .await?;
        if invite.team_id != team_id {
            return Err(TeamError::TeamInviteDoesNotExist.into());
        }
        let actor = receipt
            .get_authenticated_user()
            .map_err(|e| InviteUsersToTeamError::TeamError(TeamError::AccessError(e)))?
            .clone()
            .into_owned();

        if !self
            .team_repository
            .get_team_allow_non_admin_invites(&team_id)
            .await?
        {
            let role = self.team_repository.get_team_role(&team_id, &actor).await?;
            if !matches!(role, Some(TeamRole::Admin | TeamRole::Owner)) {
                return Err(InviteUsersToTeamError::NonAdminInvitesDisabled);
            }
        }

        let recipient = MacroUserIdStr::try_from_email(invite.email.as_ref())
            .map_err(|e| anyhow::anyhow!("invalid invitee email: {e:?}"))?
            .into_owned();
        let notification = InviteToTeamMetadata {
            team_id,
            team_invite_id: invite.team_invite_id,
            invited_by: actor.clone(),
            team_name: self.team_repository.get_team_name(&team_id).await?,
            role: None,
            sender_profile_picture_url: None,
            invitee_plan: self.resend_plan(&team_id).await?,
            reminder: false,
            is_agent: invite.is_agent,
            inviter_name: self.inviter_name(&actor).await,
        };
        let request = SendNotificationRequestBuilder {
            notification_entity: EntityType::Team.with_entity_string(invite_id.to_string()),
            secondary_notification_entity: None,
            sender_id: Some(actor),
            notification,
            recipient_ids: HashSet::from([recipient]),
        }
        .into_request()
        .with_email_outside_rate_limit();
        self.notification_ingress
            .send_notification(request)
            .await
            .map_err(|e| anyhow::anyhow!("failed to send notification: {e}"))?;

        self.team_repository.mark_invites_sent(&[invite_id]).await?;
        Ok(())
    }
}

impl<TR, CR, CS, URPS, NI, CE, TCRMS, TA, CNE, EB, OSR, OEC>
    TeamServiceImpl<TR, CR, CS, URPS, NI, CE, TCRMS, TA, CNE, EB, OSR, OEC>
where
    TR: TeamRepository,
    CR: CustomerRepository,
    CS: ChannelService + Clone,
    URPS: UserRolesAndPermissionsService,
    NI: NotificationIngress,
    CE: CrmEnqueuer,
    TCRMS: TeamCrmSettingsRepository,
    TA: TeamAnalytics,
    CNE: ContactsEnqueuer,
    EB: MacroEventBroker,
    OSR: OpenSeatRelease,
    OEC: OwnedEntityCleanup,
{
    /// The plan the email promises, following the invite reminders: no
    /// subscription backfill, so a team whose subscription is not linked yet
    /// reads as free, which never promises more than joining grants.
    async fn resend_plan(&self, team_id: &uuid::Uuid) -> Result<InviteePlan, TeamError> {
        if self
            .team_repository
            .get_team_enterprise_status(team_id)
            .await?
        {
            return Ok(InviteePlan::Premium);
        }
        let paying = self
            .team_repository
            .get_team_payment_status(team_id)
            .await?;
        let subscribed = self
            .team_repository
            .get_team_subscription_id(team_id)
            .await?
            .is_some();
        Ok(if paying && subscribed {
            InviteePlan::Premium
        } else {
            InviteePlan::Free
        })
    }
}
