//! Composition root: activation flag and wiring of the adapters.

use std::sync::Arc;

use fusionauth::FusionAuthClient;
use macro_env_var::maybe_env_vars;
use notification::domain::service::NotificationIngress;
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;
use sqlx::PgPool;
use teams::domain::team_repo::{TeamInviteLinkService, TeamService};
use teams::domain::team_service::invite_resend::ImmediateInviteResender;

use crate::domain::model::SetupToken;
use crate::domain::service::SelfHostService;
use crate::outbound::mailpit::MailpitCapture;
use crate::outbound::pg::PgSelfHostRepo;
use crate::outbound::pg_audit::PgAuditLog;
use crate::outbound::roles::RolesAdapter;
use crate::outbound::server_invites::NotificationInviter;
use crate::outbound::teams::TeamsInvites;

maybe_env_vars! {
    /// Enables self-host mode. Only the literal value `true` enables it.
    pub struct MacroSelfHosted;
    /// Reserves root for whoever signs in with this token instead of the
    /// emailed code. Unset: the first account to sign up becomes root.
    pub struct MacroSelfhostSetupToken;
    /// Address of the Mailpit that captures the server's mail, read by the
    /// admin panel. Unset: the panel says mail capture is off.
    pub struct MacroSelfhostMailCaptureUrl;
}

/// The fully wired self-host service for roles service `S`, teams service `T`
/// and notification ingress `N`.
pub type SelfHost<S, T, N> = SelfHostService<
    PgSelfHostRepo,
    RolesAdapter<S>,
    Arc<FusionAuthClient>,
    PgAuditLog,
    TeamsInvites<T>,
    NotificationInviter<N>,
    MailpitCapture,
>;

/// Whether self-host mode is enabled for this process.
pub fn enabled() -> bool {
    MacroSelfHosted::new().is_some_and(|v| v.as_ref() == "true")
}

/// Wires the Postgres repository and audit log, the roles service, FusionAuth,
/// the teams service for workspace invites, the notification service for
/// server invitations, and the mail capture. Fails on an invalid setup token
/// or mail capture address, so a misconfigured server does not start.
pub fn build<S, T, N>(
    pool: PgPool,
    roles: S,
    auth: Arc<FusionAuthClient>,
    teams: Arc<T>,
    notifications: Arc<N>,
) -> anyhow::Result<SelfHost<S, T, N>>
where
    S: UserRolesAndPermissionsService,
    T: TeamService + TeamInviteLinkService + ImmediateInviteResender,
    N: NotificationIngress,
{
    let capture = MacroSelfhostMailCaptureUrl::new()
        .filter(|v| !v.as_ref().trim().is_empty())
        .map(|v| v.as_ref().trim().parse())
        .transpose()
        .map_err(|e| anyhow::anyhow!("MACRO_SELFHOST_MAIL_CAPTURE_URL is not a URL: {e}"))?;
    let service = SelfHostService::new(
        PgSelfHostRepo::new(pool.clone()),
        RolesAdapter(roles),
        auth,
        PgAuditLog::new(pool.clone()),
        TeamsInvites::new(pool.clone(), teams),
        NotificationInviter::new(pool, notifications),
        MailpitCapture::new(capture),
    );
    match MacroSelfhostSetupToken::new().filter(|v| !v.as_ref().trim().is_empty()) {
        Some(raw) => {
            let token = SetupToken::parse(raw.as_ref())
                .map_err(|e| anyhow::anyhow!("MACRO_SELFHOST_SETUP_TOKEN: {e}"))?;
            Ok(service.with_setup_token(token))
        }
        None => Ok(service),
    }
}
