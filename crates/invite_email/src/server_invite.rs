use super::*;

/// Invites someone to sign up on a self-hosted Macro server. Sent by an
/// instance admin to an allowed address; unlike [`InviteToMacro`] it carries
/// no referral code, so signing up earns nobody a reward.
#[derive(Debug, Clone, Serialize, Deserialize, Template)]
#[template(path = "server_invite.html")]
pub struct ServerInvite {
    /// The invited address.
    pub recipient_email: EmailStr<'static>,
    /// The admin who sent the invitation.
    pub invited_by: MacroUserIdStr<'static>,
    /// The admin's display name from an untrusted source. It is shown on one
    /// line, capped, and escaped.
    pub inviter_name: Option<String>,
}

impl ServerInvite {
    /// How long one address waits between invitations. The self-host admin
    /// refuses an earlier one instead of letting the rate limit drop it.
    pub const RESEND_INTERVAL: Duration = Duration::from_hours(24 * 7);

    fn display_name(&self) -> Option<String> {
        single_line_name(self.inviter_name.as_deref())
    }

    fn inviter_email(&self) -> &str {
        self.invited_by.email_str()
    }

    /// The display name with the address, or the address alone.
    fn inviter(&self) -> String {
        match self.display_name() {
            Some(name) => format!("{name} ({})", self.inviter_email()),
            None => self.inviter_email().to_owned(),
        }
    }

    fn signup_url(&self) -> Url {
        signup_url(Environment::new_or_prod())
    }

    /// The server's host name, as people know it.
    fn server(&self) -> String {
        let url = frontend_host(Environment::new_or_prod());
        url.host_str().unwrap_or("Macro").to_owned()
    }

    fn text_body(&self) -> String {
        format!(
            "{} invited you to join them on Macro at {}.\n\n\
             Sign up with this email address to accept:\n{}\n\n\
             Questions? Reply to this email to reach the person who invited you.",
            self.inviter(),
            self.server(),
            self.signup_url(),
        )
    }
}

impl Notification for ServerInvite {
    const TYPE_NAME: &'static str = "selfhost_server_invite";
}

impl NotificationExtEmail for ServerInvite {
    fn format_email(&self) -> EmailContent {
        EmailContent {
            subject: format!("You're invited to join Macro at {}", self.server()),
            body: self
                .render()
                .expect("ServerInvite template render failed in format_email"),
            text: Some(self.text_body()),
            // An address as a display name reads as spoofing to mail filters, so an
            // admin without a name leaves the server's own sender name in place.
            from_name: self.display_name(),
            reply_to: Some(EmailStr(self.invited_by.email_part()).into_owned()),
        }
    }

    fn rate_limit_config() -> RateLimitConfig {
        RateLimitConfig {
            max_count: 1,
            window: Self::RESEND_INTERVAL,
        }
    }

    fn rate_limit_key(&self) -> RateLimitKey {
        RateLimitKey::builder(&Self::TYPE_NAME)
            .append(&self.recipient_email.0.as_ref())
            .finish()
    }
}
