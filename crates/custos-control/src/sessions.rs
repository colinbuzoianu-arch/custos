//! Login: sessions, cookies, CSRF, login-attempt rate limiting, and the
//! login audit trail. Builds on `users` (session 9, commit 2).

use crate::AppState;
use crate::users::{self, Role, UsersError};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "custos_control_session";
pub const CSRF_HEADER: &str = "x-csrf-token";

/// How long a session lives before it must be re-established by logging in
/// again.
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

// --- login rate limiting (in-memory - see ADR 0002 for why) ---------------

const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
struct Attempts {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Per-email failed-login tracking. In-memory: resets on restart, doesn't
/// share state across multiple Control instances — a deliberate v0
/// simplification (ADR 0002), not an oversight.
#[derive(Default)]
pub struct RateLimiter {
    attempts: Mutex<HashMap<String, Attempts>>,
}

impl RateLimiter {
    /// `true` if `email` is currently locked out (and should be rejected
    /// without even touching the database).
    pub fn is_locked(&self, email: &str) -> bool {
        let Ok(attempts) = self.attempts.lock() else {
            return false;
        };
        attempts
            .get(email)
            .and_then(|a| a.locked_until)
            .is_some_and(|until| Instant::now() < until)
    }

    pub fn record_failure(&self, email: &str) {
        let Ok(mut attempts) = self.attempts.lock() else {
            return;
        };
        let entry = attempts.entry(email.to_string()).or_default();
        entry.failures += 1;
        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(Instant::now() + LOCKOUT);
        }
    }

    pub fn record_success(&self, email: &str) {
        let Ok(mut attempts) = self.attempts.lock() else {
            return;
        };
        attempts.remove(email);
    }
}

// --- login / logout ---------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("too many failed attempts, try again later")]
    LockedOut,
    #[error("invalid tenant, email, or password")]
    InvalidCredentials,
    #[error(transparent)]
    Users(#[from] UsersError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub struct LoggedIn {
    pub session_id: Uuid,
    pub csrf_token: String,
    pub role: Role,
}

/// Attempts a login. Records the attempt (success or failure) to
/// `login_audit` either way — that's the point of an audit trail. Checks
/// the rate limiter *before* touching the database, so a locked-out email
/// can't be used to hammer Postgres either.
pub async fn login(
    db: &PgPool,
    limiter: &RateLimiter,
    tenant_slug: &str,
    email: &str,
    password: &str,
) -> Result<LoggedIn, LoginError> {
    if limiter.is_locked(email) {
        return Err(LoginError::LockedOut);
    }

    let tenant_id = users::find_tenant_by_slug(db, tenant_slug).await?;
    let user = match tenant_id {
        Some(tid) => users::find_user_by_email(db, tid, email).await?,
        None => None,
    };

    let ok = match &user {
        Some(u) => users::verify_password(password, &u.password_hash),
        None => false,
    };

    record_login_audit(db, tenant_id, email, ok).await;

    if !ok {
        limiter.record_failure(email);
        return Err(LoginError::InvalidCredentials);
    }
    limiter.record_success(email);

    // Safe: `ok` is only true when `user` is `Some` (verify_password needs
    // a real hash to check against).
    let Some(user) = user else {
        return Err(LoginError::InvalidCredentials);
    };

    let csrf_token = Uuid::new_v4().to_string();
    let expires_at = time::OffsetDateTime::now_utc() + SESSION_TTL;
    let session_id: (Uuid,) = sqlx::query_as(
        "insert into sessions (user_id, tenant_id, csrf_token, expires_at) values ($1, $2, $3, $4) returning id",
    )
    .bind(user.id)
    .bind(user.tenant_id)
    .bind(&csrf_token)
    .bind(expires_at)
    .fetch_one(db)
    .await?;

    Ok(LoggedIn {
        session_id: session_id.0,
        csrf_token,
        role: user.role,
    })
}

async fn record_login_audit(db: &PgPool, tenant_id: Option<Uuid>, email: &str, success: bool) {
    // A failure to audit a login attempt shouldn't itself block the login
    // outcome that was already decided above (unlike a gateway tool call,
    // where invariant 3 makes the audit write load-bearing) - but it is
    // logged, since losing audit coverage silently would be worse.
    let result =
        sqlx::query("insert into login_audit (tenant_id, email, success) values ($1, $2, $3)")
            .bind(tenant_id)
            .bind(email)
            .bind(success)
            .execute(db)
            .await;
    if let Err(e) = result {
        tracing::error!(error = %e, email, "failed to write login_audit");
    }
}

pub async fn logout(db: &PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("delete from sessions where id = $1")
        .bind(session_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Builds the `Set-Cookie` for a new session: `HttpOnly`, `Secure`,
/// `SameSite=Strict` — never readable from JavaScript, never sent
/// cross-site, never sent over plain HTTP.
pub fn session_cookie(session_id: Uuid) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, session_id.to_string()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(SESSION_TTL.as_secs() as i64))
        .build()
}

pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build()
}

// --- the CurrentUser extractor -----------------------------------------

/// Whoever the request's session cookie identifies. Extracting this (via
/// `axum`'s `FromRequestParts`) is how every route past `/login` checks
/// authentication — there's no other way to get one.
pub struct CurrentUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub role: Role,
    pub session_id: Uuid,
    csrf_token: String,
}

impl CurrentUser {
    /// This session's CSRF token — handed back by `/me` so a page refresh
    /// (which keeps the HttpOnly session cookie but loses anything the
    /// dashboard only held in memory) can recover it without a fresh
    /// login.
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// Checks `X-CSRF-Token` against this session's token. Call this in
    /// every handler that mutates state (not needed for a plain read).
    pub fn check_csrf(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let sent = headers
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if sent == self.csrf_token && !sent.is_empty() {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

impl FromRequestParts<std::sync::Arc<AppState>> for CurrentUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &std::sync::Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let session_id = jar
            .get(SESSION_COOKIE)
            .and_then(|c| Uuid::parse_str(c.value()).ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let row: Option<(Uuid, Uuid, String, String, time::OffsetDateTime)> = sqlx::query_as(
            "select sessions.user_id, sessions.tenant_id, users.role, sessions.csrf_token, sessions.expires_at
             from sessions join users on users.id = sessions.user_id
             where sessions.id = $1",
        )
        .bind(session_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let (user_id, tenant_id, role, csrf_token, expires_at) =
            row.ok_or(StatusCode::UNAUTHORIZED)?;

        if time::OffsetDateTime::now_utc() >= expires_at {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let role: Role = role.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(CurrentUser {
            user_id,
            tenant_id,
            role,
            session_id,
            csrf_token,
        })
    }
}

/// Same as [`CurrentUser`], but rejects with `403 Forbidden` for anyone
/// whose role isn't `admin`. Use this as the extractor type on a route
/// instead of `CurrentUser` to gate it to admins only.
pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<std::sync::Arc<AppState>> for AdminUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &std::sync::Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.role == Role::Admin {
            Ok(AdminUser(user))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Same as [`CurrentUser`], but rejects with `403 Forbidden` for anyone
/// whose role isn't `approver` or `admin` — the two roles the plan allows
/// to resolve a held call.
pub struct ApproverUser(pub CurrentUser);

impl FromRequestParts<std::sync::Arc<AppState>> for ApproverUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &std::sync::Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if matches!(user.role, Role::Admin | Role::Approver) {
            Ok(ApproverUser(user))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_max_failures() {
        let limiter = RateLimiter::default();
        assert!(!limiter.is_locked("a@example.com"));
        for _ in 0..MAX_FAILURES - 1 {
            limiter.record_failure("a@example.com");
            assert!(!limiter.is_locked("a@example.com"));
        }
        limiter.record_failure("a@example.com");
        assert!(limiter.is_locked("a@example.com"));
    }

    #[test]
    fn success_resets_the_failure_count() {
        let limiter = RateLimiter::default();
        for _ in 0..MAX_FAILURES - 1 {
            limiter.record_failure("a@example.com");
        }
        limiter.record_success("a@example.com");
        // One more failure shouldn't be enough to lock out right after a
        // reset, since the count started over.
        limiter.record_failure("a@example.com");
        assert!(!limiter.is_locked("a@example.com"));
    }

    #[test]
    fn lockout_is_per_email() {
        let limiter = RateLimiter::default();
        for _ in 0..MAX_FAILURES {
            limiter.record_failure("locked@example.com");
        }
        assert!(limiter.is_locked("locked@example.com"));
        assert!(!limiter.is_locked("other@example.com"));
    }

    fn user_with_csrf(token: &str) -> CurrentUser {
        CurrentUser {
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role: Role::Admin,
            session_id: Uuid::new_v4(),
            csrf_token: token.to_string(),
        }
    }

    #[test]
    fn matching_csrf_token_passes() {
        let user = user_with_csrf("secret-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            CSRF_HEADER,
            axum::http::HeaderValue::from_static("secret-token"),
        );
        assert!(user.check_csrf(&headers).is_ok());
    }

    #[test]
    fn missing_csrf_header_is_rejected() {
        let user = user_with_csrf("secret-token");
        assert_eq!(
            user.check_csrf(&HeaderMap::new()),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn wrong_csrf_token_is_rejected() {
        let user = user_with_csrf("secret-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            CSRF_HEADER,
            axum::http::HeaderValue::from_static("wrong-token"),
        );
        assert_eq!(user.check_csrf(&headers), Err(StatusCode::FORBIDDEN));
    }
}
