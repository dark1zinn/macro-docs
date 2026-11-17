//! Composition root: activation flag and wiring of the adapters.

use std::sync::Arc;

use fusionauth::FusionAuthClient;
use macro_env_var::maybe_env_vars;
use notification::domain::service::NotificationIngress;
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;
use sqlx::PgPool;
use teams::domain::team_repo::{TeamInviteLinkService, TeamService};
use teams::domain::team_service::invite_resend::ImmediateInviteResender;

use crate::domain::service::SelfHostService;
use crate::outbound::pg::PgSelfHostRepo;
use crate::outbound::pg_audit::PgAuditLog;
use crate::outbound::roles::RolesAdapter;
use crate::outbound::server_invites::NotificationInviter;
use crate::outbound::teams::TeamsInvites;

maybe_env_vars! {
    /// Enables self-host mode. Only the literal value `true` enables it.
    pub struct MacroSelfHosted;
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
>;

/// Whether self-host mode is enabled for this process.
pub fn enabled() -> bool {
    MacroSelfHosted::new().is_some_and(|v| v.as_ref() == "true")
}

/// Wires the Postgres repository and audit log, the roles service, FusionAuth,
/// the teams service for workspace invites, and the notification service for
/// server invitations.
pub fn build<S, T, N>(
    pool: PgPool,
    roles: S,
    auth: Arc<FusionAuthClient>,
    teams: Arc<T>,
    notifications: Arc<N>,
) -> SelfHost<S, T, N>
where
    S: UserRolesAndPermissionsService,
    T: TeamService + TeamInviteLinkService + ImmediateInviteResender,
    N: NotificationIngress,
{
    SelfHostService::new(
        PgSelfHostRepo::new(pool.clone()),
        RolesAdapter(roles),
        auth,
        PgAuditLog::new(pool.clone()),
        TeamsInvites::new(pool.clone(), teams),
        NotificationInviter::new(pool, notifications),
    )
}
