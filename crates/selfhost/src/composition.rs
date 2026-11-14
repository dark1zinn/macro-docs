//! Composition root: activation flag and wiring of the adapters.

use std::sync::Arc;

use fusionauth::FusionAuthClient;
use macro_env_var::maybe_env_vars;
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;
use sqlx::PgPool;

use crate::domain::service::SelfHostService;
use crate::outbound::pg::PgSelfHostRepo;
use crate::outbound::pg_audit::PgAuditLog;
use crate::outbound::roles::RolesAdapter;

maybe_env_vars! {
    /// Enables self-host mode. Only the literal value `true` enables it.
    pub struct MacroSelfHosted;
}

/// The fully wired self-host service for a given roles service `S`.
pub type SelfHost<S> =
    SelfHostService<PgSelfHostRepo, RolesAdapter<S>, Arc<FusionAuthClient>, PgAuditLog>;

/// Whether self-host mode is enabled for this process.
pub fn enabled() -> bool {
    MacroSelfHosted::new().is_some_and(|v| v.as_ref() == "true")
}

/// Wires the Postgres repository and audit log, the roles service, and FusionAuth.
pub fn build<S: UserRolesAndPermissionsService>(
    pool: PgPool,
    roles: S,
    auth: Arc<FusionAuthClient>,
) -> SelfHost<S> {
    SelfHostService::new(
        PgSelfHostRepo::new(pool.clone()),
        RolesAdapter(roles),
        auth,
        PgAuditLog::new(pool),
    )
}
