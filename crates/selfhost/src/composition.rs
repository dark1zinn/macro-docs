//! Composition root: activation flag and wiring of the adapters.

use std::sync::Arc;

use fusionauth::FusionAuthClient;
use macro_env_var::maybe_env_vars;
use referral::domain::ports::ReferralService;
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;
use sqlx::PgPool;
use teams::domain::team_repo::{TeamInviteLinkService, TeamService};

use crate::domain::service::SelfHostService;
use crate::outbound::pg::PgSelfHostRepo;
use crate::outbound::pg_audit::PgAuditLog;
use crate::outbound::referral::ReferralInviter;
use crate::outbound::roles::RolesAdapter;
use crate::outbound::teams::TeamsInvites;

maybe_env_vars! {
    /// Enables self-host mode. Only the literal value `true` enables it.
    pub struct MacroSelfHosted;
}

/// The fully wired self-host service for roles service `S`, teams service `T`
/// and referral service `F`.
pub type SelfHost<S, T, F> = SelfHostService<
    PgSelfHostRepo,
    RolesAdapter<S>,
    Arc<FusionAuthClient>,
    PgAuditLog,
    TeamsInvites<T>,
    ReferralInviter<F>,
>;

/// Whether self-host mode is enabled for this process.
pub fn enabled() -> bool {
    MacroSelfHosted::new().is_some_and(|v| v.as_ref() == "true")
}

/// Wires the Postgres repository and audit log, the roles service, FusionAuth,
/// the teams service for workspace invites, and the referral service for
/// server invitations.
pub fn build<S, T, F>(
    pool: PgPool,
    roles: S,
    auth: Arc<FusionAuthClient>,
    teams: Arc<T>,
    referral: Arc<F>,
) -> SelfHost<S, T, F>
where
    S: UserRolesAndPermissionsService,
    T: TeamService + TeamInviteLinkService,
    F: ReferralService,
{
    SelfHostService::new(
        PgSelfHostRepo::new(pool.clone()),
        RolesAdapter(roles),
        auth,
        PgAuditLog::new(pool.clone()),
        TeamsInvites::new(pool, teams),
        ReferralInviter(referral),
    )
}
