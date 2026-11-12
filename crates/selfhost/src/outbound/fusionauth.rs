//! FusionAuth adapter for [`AccountPort`](crate::domain::ports::AccountPort).

use std::sync::Arc;

use async_trait::async_trait;
use fusionauth::FusionAuthClient;

use crate::domain::ports::AccountPort;

#[async_trait]
impl AccountPort for Arc<FusionAuthClient> {
    async fn set_active(&self, user_id: &str, active: bool) -> anyhow::Result<()> {
        if active {
            Ok(self.reactivate_user(user_id).await?)
        } else {
            Ok(self.deactivate_user(user_id).await?)
        }
    }
}
