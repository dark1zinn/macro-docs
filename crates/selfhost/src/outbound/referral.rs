//! [`ServerInviter`] over the referral service's "join Macro" email.

use std::sync::Arc;

use async_trait::async_trait;
use macro_user_id::email::EmailStr;
use macro_user_id::user_id::MacroUserIdStr;
use referral::domain::ports::ReferralService;

use crate::domain::ports::ServerInviter;

/// Sends server invitations through the referral service `F`, which emails the
/// "join Macro" template with a sign-up link to this server.
pub struct ReferralInviter<F>(pub Arc<F>);

#[async_trait]
impl<F: ReferralService> ServerInviter for ReferralInviter<F> {
    async fn invite(&self, admin: &str, email: &str) -> anyhow::Result<()> {
        let sender = MacroUserIdStr::parse_from_str(admin)
            .map_err(|e| anyhow::anyhow!("invalid admin id: {e:?}"))?;
        let recipient = EmailStr::try_from(email.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid invite email: {e:?}"))?;
        self.0
            .send_referral_invite(sender, recipient)
            .await
            .map_err(|e| anyhow::anyhow!("sending server invite: {e}"))
    }
}
