//! Adapter from the roles service to [`RolesPort`](crate::domain::ports::RolesPort).

use std::collections::HashSet;

use async_trait::async_trait;
use macro_user_id::user_id::MacroUserIdStr;
use non_empty::NonEmpty;
use roles_and_permissions::domain::model::RoleId;
use roles_and_permissions::domain::port::UserRolesAndPermissionsService;

use crate::domain::ports::RolesPort;

/// Wraps the roles service so the self-host domain can use [`RolesPort`].
#[derive(Clone)]
pub struct RolesAdapter<S>(pub S);

fn parse_macro_id(macro_user_id: &str) -> anyhow::Result<MacroUserIdStr<'_>> {
    MacroUserIdStr::parse_from_str(macro_user_id)
        .map_err(|e| anyhow::anyhow!("invalid macro user id: {e}"))
}

#[async_trait]
impl<S: UserRolesAndPermissionsService> RolesPort for RolesAdapter<S> {
    async fn get_roles(&self, macro_user_id: &str) -> anyhow::Result<HashSet<RoleId>> {
        let id = parse_macro_id(macro_user_id)?;
        Ok(self.0.get_user_roles(&id).await?)
    }

    async fn grant_roles(&self, macro_user_id: &str, roles: &[RoleId]) -> anyhow::Result<()> {
        let id = parse_macro_id(macro_user_id)?;
        let roles = NonEmpty::new(roles).map_err(|_| anyhow::anyhow!("no roles to grant"))?;
        self.0.dangerous_upsert_roles_for_user(&id, roles).await?;
        Ok(())
    }
}
