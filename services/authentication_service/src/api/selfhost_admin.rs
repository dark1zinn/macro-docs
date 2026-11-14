//! Self-host admin routes and the signup gate. Mounted only when self-host mode
//! is enabled. Domain rules live in the `selfhost` crate; this module maps HTTP
//! to it.

use crate::api::context::{ApiContext, AuthorizationService};
use crate::api::signup_policy::signup_forbidden_response;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use macro_authorization::{MacroAuthorizationExtractor, UserOnly};
use selfhost::domain::model::{
    AuditAction, AuditEntry, AuditQuery, AuditStatus, SelfHostError, SignupPolicy, UserEntry,
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

fn error_response(error: SelfHostError) -> Response {
    let (status, message) = match error {
        SelfHostError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
        SelfHostError::Forbidden => (StatusCode::FORBIDDEN, "admin role required".into()),
        SelfHostError::NotFound => (StatusCode::NOT_FOUND, "user not found".into()),
        SelfHostError::Conflict(message) => (StatusCode::CONFLICT, message),
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
    Ok(Json(SignupsResponse {
        policy: policy.as_str(),
        allowed_emails: allowed
            .into_iter()
            .map(|a| AllowedEmailItem {
                email: a.email,
                created_at: a.created_at,
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
    Json(body): Json<EmailBody>,
) -> Result<StatusCode, Response> {
    let svc = ctx.selfhost.clone().ok_or_else(disabled_response)?;
    svc.add_allowed_email(user.authorization.macro_user_id.as_ref(), &body.email)
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
        .route("/selfhost/admin/audit", get(list_audit))
        .route("/selfhost/admin/audit/export", get(export_audit))
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
