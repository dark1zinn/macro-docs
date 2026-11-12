//! Self-host admin routes and the signup gate. Mounted only when self-host mode
//! is enabled. Domain rules live in the `selfhost` crate; this module maps HTTP
//! to it.

use crate::api::context::{ApiContext, AuthorizationService};
use crate::api::signup_policy::signup_forbidden_response;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use macro_authorization::{MacroAuthorizationExtractor, UserOnly};
use selfhost::domain::model::{SelfHostError, SignupPolicy, UserEntry};
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
