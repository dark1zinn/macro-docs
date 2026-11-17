//! Self-host admin routes and the signup gate. Mounted only when self-host mode
//! is enabled. Domain rules live in the `selfhost` crate; this module maps HTTP
//! to it.

use crate::api::context::{ApiContext, AuthorizationService};
use crate::api::signup_policy::signup_forbidden_response;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use macro_authorization::{MacroAuthorizationExtractor, UserOnly};
use selfhost::domain::model::{
    AuditAction, AuditEntry, AuditQuery, AuditStatus, BulkOutcome, CapturedMail, InvitesOverview,
    MailQuery, SelfHostError, SignupPolicy, UserEntry,
};
use serde::{Deserialize, Serialize};

type User = MacroAuthorizationExtractor<AuthorizationService, UserOnly>;

#[derive(Serialize)]
struct ErrorBody {
    message: String,
}

#[derive(Serialize)]
struct UserItem {
    user_id: String,
    email: String,
    created_at: Option<DateTime<Utc>>,
    is_admin: bool,
    disabled: bool,
    is_self: bool,
}

impl From<UserEntry> for UserItem {
    fn from(entry: UserEntry) -> Self {
        Self {
            user_id: entry.record.user_id,
            email: entry.record.email,
            created_at: entry.record.created_at,
            is_admin: entry.record.is_admin,
            disabled: entry.record.disabled,
            is_self: entry.is_self,
        }
    }
}

#[derive(Serialize)]
struct UsersResponse {
    users: Vec<UserItem>,
}

#[derive(Serialize)]
struct AllowedEmailItem {
    email: String,
    created_at: DateTime<Utc>,
    last_invited_at: Option<DateTime<Utc>>,
    /// When the address can be sent a server invitation again; absent when it can be now.
    invitable_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct SignupsResponse {
    policy: &'static str,
    allowed_emails: Vec<AllowedEmailItem>,
}

#[derive(Deserialize)]
struct SetAdminBody {
    user_id: String,
    admin: bool,
}

#[derive(Deserialize)]
struct SetDisabledBody {
    user_id: String,
    disabled: bool,
}

#[derive(Deserialize)]
struct PolicyBody {
    policy: String,
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
struct AllowEmailBody {
    email: String,
    /// Also email the person an invitation to sign up.
    #[serde(default)]
    notify: bool,
}

#[derive(Deserialize)]
struct TeamBody {
    team_id: uuid::Uuid,
}

#[derive(Deserialize)]
struct InviteBody {
    invite_id: uuid::Uuid,
}

#[derive(Deserialize)]
struct ResendBody {
    invite_id: uuid::Uuid,
    /// Send it even inside its resend window.
    #[serde(default)]
    now: bool,
}

#[derive(Serialize)]
struct BulkFailureItem {
    target: String,
    error: String,
}

#[derive(Serialize)]
struct RevokedResponse {
    revoked: usize,
    failed: Vec<BulkFailureItem>,
}

impl From<BulkOutcome> for RevokedResponse {
    fn from(outcome: BulkOutcome) -> Self {
        Self {
            revoked: outcome.succeeded,
            failed: outcome
                .failures
                .into_iter()
                .map(|f| BulkFailureItem {
                    target: f.target,
                    error: f.error,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct InviteLinkItem {
    team_id: uuid::Uuid,
    team_name: String,
    token: uuid::Uuid,
    created_at: DateTime<Utc>,
    /// Macro user id of whoever created or last replaced the link.
    created_by: Option<String>,
}

#[derive(Serialize)]
struct PendingInviteItem {
    invite_id: uuid::Uuid,
    team_id: uuid::Uuid,
    team_name: String,
    email: String,
    invited_by: String,
    created_at: DateTime<Utc>,
    last_sent_at: DateTime<Utc>,
    resendable_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct InvitesResponse {
    links: Vec<InviteLinkItem>,
    invites: Vec<PendingInviteItem>,
}

impl From<InvitesOverview> for InvitesResponse {
    fn from(overview: InvitesOverview) -> Self {
        Self {
            links: overview
                .links
                .into_iter()
                .map(|l| InviteLinkItem {
                    team_id: l.team_id,
                    team_name: l.team_name,
                    token: l.token,
                    created_at: l.created_at,
                    created_by: l.created_by,
                })
                .collect(),
            invites: overview
                .invites
                .into_iter()
                .map(|i| PendingInviteItem {
                    invite_id: i.invite_id,
                    team_id: i.team_id,
                    team_name: i.team_name,
                    email: i.email,
                    invited_by: i.invited_by,
                    created_at: i.created_at,
                    last_sent_at: i.last_sent_at,
                    resendable_at: i.resendable_at,
                })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
struct AuditParams {
    action: Option<String>,
    search: Option<String>,
    before: Option<i64>,
    limit: Option<i64>,
}

impl AuditParams {
    fn into_query(self) -> Result<AuditQuery, SelfHostError> {
        let action =
            match self.action.as_deref().filter(|a| !a.is_empty()) {
                None => None,
                Some(raw) => Some(AuditAction::parse(raw).ok_or_else(|| {
                    SelfHostError::Invalid(format!("unknown audit action {raw:?}"))
                })?),
            };
        Ok(AuditQuery {
            action,
            search: self.search,
            before: self.before,
            limit: self.limit,
        })
    }
}

#[derive(Serialize)]
struct AuditItem {
    id: i64,
    created_at: DateTime<Utc>,
    /// Macro user id of the admin; absent for system actions.
    actor: Option<String>,
    action: &'static str,
    target: Option<String>,
    details: serde_json::Value,
    status: &'static str,
    error: Option<String>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<AuditEntry> for AuditItem {
    fn from(entry: AuditEntry) -> Self {
        let (status, error) = match entry.status {
            AuditStatus::Pending => ("pending", None),
            AuditStatus::Succeeded => ("succeeded", None),
            AuditStatus::Failed(error) => ("failed", Some(error)),
        };
        Self {
            id: entry.id,
            created_at: entry.created_at,
            actor: entry.entry.actor,
            action: entry.entry.action.as_str(),
            target: entry.entry.target,
            details: entry.entry.details,
            status,
            error,
            completed_at: entry.completed_at,
        }
    }
}

#[derive(Serialize)]
struct AuditResponse {
    entries: Vec<AuditItem>,
    /// Cursor for the next (older) page; absent once a page comes back empty.
    next_before: Option<i64>,
}

#[derive(Deserialize)]
struct MailParams {
    search: Option<String>,
    #[serde(default)]
    start: u32,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct MailIdBody {
    id: String,
}

#[derive(Serialize)]
struct MailItem {
    id: String,
    from: String,
    to: Vec<String>,
    subject: String,
    created_at: DateTime<Utc>,
    snippet: String,
}

impl From<CapturedMail> for MailItem {
    fn from(m: CapturedMail) -> Self {
        Self {
            id: m.id,
            from: m.from,
            to: m.to,
            subject: m.subject,
            created_at: m.created_at,
            snippet: m.snippet,
        }
    }
}

#[derive(Serialize)]
struct MailResponse {
    messages: Vec<MailItem>,
    total: u32,
}

#[derive(Serialize)]
struct MailMessageResponse {
    #[serde(flatten)]
    mail: MailItem,
    text: Option<String>,
    /// Untrusted HTML; the panel renders it in a sandboxed frame.
    html: Option<String>,
}

fn error_response(error: SelfHostError) -> Response {
    let (status, message) = match error {
        SelfHostError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
        SelfHostError::Forbidden => (StatusCode::FORBIDDEN, "admin role required".into()),
        SelfHostError::NotFound(what) => (StatusCode::NOT_FOUND, format!("{what} not found")),
        SelfHostError::Conflict(message) => (StatusCode::CONFLICT, message),
        SelfHostError::Unavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message),
        SelfHostError::Internal(error) => {
            tracing::error!(error=?error, "self-host operation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
        }
    };
    (status, Json(ErrorBody { message })).into_response()
}

/// Returns a 404 when self-host mode is off, so the routes behave as absent.
fn disabled_response() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn list_users(
    State(ctx): State<ApiContext>,
    user: User,
) -> Result<Json<UsersResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let entries = svc
        .list_users(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    Ok(Json(UsersResponse {
        users: entries.into_iter().map(UserItem::from).collect(),
    }))
}

async fn set_admin(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<SetAdminBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.set_admin(
        user.authorization.macro_user_id.as_ref(),
        &body.user_id,
        body.admin,
    )
    .await
    .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_disabled(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<SetDisabledBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.set_disabled(
        user.authorization.macro_user_id.as_ref(),
        &body.user_id,
        body.disabled,
    )
    .await
    .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_signups(
    State(ctx): State<ApiContext>,
    user: User,
) -> Result<Json<SignupsResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let (policy, allowed) = svc
        .get_signups(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    let interval = chrono::Duration::from_std(svc.server_invite_interval())
        .map_err(|e| error_response(SelfHostError::Internal(e.into())))?;
    let now = Utc::now();
    Ok(Json(SignupsResponse {
        policy: policy.as_str(),
        allowed_emails: allowed
            .into_iter()
            .map(|a| AllowedEmailItem {
                invitable_at: a
                    .last_invited_at
                    .map(|at| at + interval)
                    .filter(|at| *at > now),
                email: a.email,
                created_at: a.created_at,
                last_invited_at: a.last_invited_at,
            })
            .collect(),
    }))
}

async fn set_policy(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<PolicyBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let policy = SignupPolicy::parse(&body.policy).ok_or_else(|| {
        error_response(SelfHostError::Invalid(
            "policy must be open or invite_only".into(),
        ))
    })?;
    svc.set_policy(user.authorization.macro_user_id.as_ref(), policy)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_allowed_email(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<AllowEmailBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.add_allowed_email(
        user.authorization.macro_user_id.as_ref(),
        &body.email,
        body.notify,
    )
    .await
    .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn invite_allowed_email(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<EmailBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.invite_allowed_email(user.authorization.macro_user_id.as_ref(), &body.email)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_invites(
    State(ctx): State<ApiContext>,
    user: User,
) -> Result<Json<InvitesResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let overview = svc
        .list_invites(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    Ok(Json(overview.into()))
}

async fn revoke_invite_link(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<TeamBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.revoke_invite_link(user.authorization.macro_user_id.as_ref(), body.team_id)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_all_invite_links(
    State(ctx): State<ApiContext>,
    user: User,
) -> Result<Json<RevokedResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let outcome = svc
        .revoke_all_invite_links(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    Ok(Json(outcome.into()))
}

async fn revoke_invite(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<InviteBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.revoke_invite(user.authorization.macro_user_id.as_ref(), body.invite_id)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_all_invites(
    State(ctx): State<ApiContext>,
    user: User,
) -> Result<Json<RevokedResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let outcome = svc
        .revoke_all_invites(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    Ok(Json(outcome.into()))
}

async fn resend_invite(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<ResendBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.resend_invite(
        user.authorization.macro_user_id.as_ref(),
        body.invite_id,
        body.now,
    )
    .await
    .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_allowed_email(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<EmailBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.remove_allowed_email(user.authorization.macro_user_id.as_ref(), &body.email)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Admin routes when self-host mode is on; an empty router otherwise.
pub(crate) fn router_if_enabled(state: &ApiContext) -> Router<ApiContext> {
    if state.selfhost.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/selfhost/admin/users", get(list_users))
        .route("/selfhost/admin/users/admin", post(set_admin))
        .route("/selfhost/admin/users/disabled", post(set_disabled))
        .route("/selfhost/admin/signups", get(get_signups))
        .route("/selfhost/admin/signups/policy", put(set_policy))
        .route(
            "/selfhost/admin/signups/allowed_emails",
            post(add_allowed_email),
        )
        .route(
            "/selfhost/admin/signups/allowed_emails/remove",
            post(remove_allowed_email),
        )
        .route(
            "/selfhost/admin/signups/allowed_emails/invite",
            post(invite_allowed_email),
        )
        .route("/selfhost/admin/invites", get(list_invites))
        .route(
            "/selfhost/admin/invites/links/revoke",
            post(revoke_invite_link),
        )
        .route(
            "/selfhost/admin/invites/links/revoke_all",
            post(revoke_all_invite_links),
        )
        .route("/selfhost/admin/invites/revoke", post(revoke_invite))
        .route(
            "/selfhost/admin/invites/revoke_all",
            post(revoke_all_invites),
        )
        .route("/selfhost/admin/invites/resend", post(resend_invite))
        .route("/selfhost/admin/audit", get(list_audit))
        .route("/selfhost/admin/audit/export", get(export_audit))
        .route("/selfhost/admin/mail", get(list_mail))
        .route("/selfhost/admin/mail/{id}", get(get_mail))
        .route("/selfhost/admin/mail/delete", post(delete_mail))
        .route("/selfhost/admin/mail/clear", post(clear_mail))
}

/// One page of the mail the server sent and Mailpit captured.
async fn list_mail(
    State(ctx): State<ApiContext>,
    user: User,
    Query(params): Query<MailParams>,
) -> Result<Json<MailResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let page = svc
        .list_captured_mail(
            user.authorization.macro_user_id.as_ref(),
            MailQuery {
                search: params.search,
                start: params.start,
                limit: params.limit,
            },
        )
        .await
        .map_err(error_response)?;
    Ok(Json(MailResponse {
        messages: page.messages.into_iter().map(MailItem::from).collect(),
        total: page.total,
    }))
}

async fn get_mail(
    State(ctx): State<ApiContext>,
    user: User,
    Path(id): Path<String>,
) -> Result<Json<MailMessageResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let message = svc
        .captured_message(user.authorization.macro_user_id.as_ref(), &id)
        .await
        .map_err(error_response)?;
    Ok(Json(MailMessageResponse {
        mail: message.mail.into(),
        text: message.text,
        html: message.html,
    }))
}

async fn delete_mail(
    State(ctx): State<ApiContext>,
    user: User,
    Json(body): Json<MailIdBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.delete_captured_mail(user.authorization.macro_user_id.as_ref(), &body.id)
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_mail(State(ctx): State<ApiContext>, user: User) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.clear_captured_mail(user.authorization.macro_user_id.as_ref())
        .await
        .map_err(error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_audit(
    State(ctx): State<ApiContext>,
    user: User,
    Query(params): Query<AuditParams>,
) -> Result<Json<AuditResponse>, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let entries = svc
        .list_audit(
            user.authorization.macro_user_id.as_ref(),
            params.into_query().map_err(error_response)?,
        )
        .await
        .map_err(error_response)?;
    Ok(Json(AuditResponse {
        next_before: entries.last().map(|entry| entry.id),
        entries: entries.into_iter().map(AuditItem::from).collect(),
    }))
}

/// Every entry matching the filters, newest first, as a CSV download.
async fn export_audit(
    State(ctx): State<ApiContext>,
    user: User,
    Query(params): Query<AuditParams>,
) -> Result<Response, Response> {
    const PAGE: i64 = 200;
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    let caller = user.authorization.macro_user_id.as_ref();
    let filter = params.into_query().map_err(error_response)?;
    let mut entries = Vec::new();
    loop {
        let page = svc
            .list_audit(
                caller,
                AuditQuery {
                    before: entries.last().map(|entry: &AuditEntry| entry.id),
                    limit: Some(PAGE),
                    ..filter.clone()
                },
            )
            .await
            .map_err(error_response)?;
        let done = i64::try_from(page.len()).unwrap_or(PAGE) < PAGE;
        entries.extend(page);
        if done {
            break;
        }
    }
    let csv = selfhost::export::audit_csv(&entries)
        .map_err(|error| error_response(SelfHostError::Internal(error)))?;
    // Bytes, not text/csv: the web client's fetch helper returns raw bodies only
    // for octet-stream, and the panel saves them as a CSV file.
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"selfhost-audit-log.csv\"",
            ),
        ],
        csv,
    )
        .into_response())
}

/// Returns a denial response when self-host mode is on and the email may not
/// sign up. `None` means proceed, including whenever self-host mode is off.
pub(crate) async fn signup_denied(ctx: &ApiContext, email: &str) -> Option<Response> {
    let svc = ctx.selfhost.as_ref()?;
    match svc.authorize_signup(email).await {
        Ok(true) => None,
        Ok(false) => Some(signup_forbidden_response()),
        Err(error) => {
            tracing::error!(error=?error, "self-host signup check failed; denying");
            Some(signup_forbidden_response())
        }
    }
}

/// Whether `code` is the self-host setup token and root is still unclaimed.
/// `false` whenever self-host mode is off or the check fails.
pub(crate) async fn setup_token_accepted(ctx: &ApiContext, code: &str) -> bool {
    let Some(svc) = ctx.selfhost.as_ref() else {
        return false;
    };
    svc.setup_token_accepted(code)
        .await
        .inspect_err(|error| tracing::error!(error=?error, "self-host setup token check failed"))
        .unwrap_or(false)
}

/// Makes `email` root after it signed in with the setup token. The sign-in
/// stands either way; a lost race leaves the account a regular user.
pub(crate) async fn claim_root_with_setup_token(ctx: &ApiContext, email: &str) {
    let Some(svc) = ctx.selfhost.as_ref() else {
        return;
    };
    match svc.claim_root_with_setup_token(email).await {
        Ok(true) => {}
        Ok(false) => tracing::warn!("setup token sign-in did not claim root; it was already taken"),
        Err(error) => tracing::error!(error=?error, "self-host root claim failed"),
    }
}
