//! Users, tenants, and Argon2id password hashing. Login (sessions, cookies,
//! CSRF, rate limiting) is the next commit — this is just the data these
//! build on, plus the pieces `create-admin` needs.

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum UsersError {
    #[error("could not hash password: {0}")]
    Hash(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("{tenant_id} already has a user with email {email}")]
    UserExists { tenant_id: Uuid, email: String },
}

/// Who a user is allowed to do, in Control. `admin` manages agents,
/// policies and other users; `approver` can act on `Hold` decisions
/// (session 16); `viewer` reads only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Approver,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Approver => "approver",
            Role::Viewer => "viewer",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "approver" => Ok(Role::Approver),
            "viewer" => Ok(Role::Viewer),
            other => Err(format!("unknown role {other:?}")),
        }
    }
}

pub struct UserRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: Role,
}

/// Hashes `password` with Argon2id and a fresh random salt. The output
/// string carries the algorithm, parameters and salt, so `verify_password`
/// needs nothing else to check a later attempt against it.
pub fn hash_password(password: &str) -> Result<String, UsersError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| UsersError::Hash(e.to_string()))
}

/// `false` for a wrong password *and* for a malformed stored hash — a
/// corrupt hash must never be treated as "no password required".
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Postgres' code for a unique-constraint violation (`unique_violation`).
const UNIQUE_VIOLATION: &str = "23505";

pub async fn find_tenant_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Uuid>, sqlx::Error> {
    let row: Option<(Uuid,)> = sqlx::query_as("select id from tenants where slug = $1")
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

pub async fn create_tenant(pool: &PgPool, slug: &str, name: &str) -> Result<Uuid, sqlx::Error> {
    let row: (Uuid,) =
        sqlx::query_as("insert into tenants (slug, name) values ($1, $2) returning id")
            .bind(slug)
            .bind(name)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Creates a user with an already-hashed password. `Err(UserExists)`
/// rather than a raw DB error if `(tenant_id, email)` is already taken —
/// this is the case `create-admin` needs to report clearly, not just as
/// "database error: 23505".
pub async fn create_user(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    password_hash: &str,
    role: Role,
) -> Result<Uuid, UsersError> {
    let result: Result<(Uuid,), sqlx::Error> = sqlx::query_as(
        "insert into users (tenant_id, email, password_hash, role) values ($1, $2, $3, $4) returning id",
    )
    .bind(tenant_id)
    .bind(email)
    .bind(password_hash)
    .bind(role.as_str())
    .fetch_one(pool)
    .await;

    match result {
        Ok((id,)) => Ok(id),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNIQUE_VIOLATION) => {
            Err(UsersError::UserExists {
                tenant_id,
                email: email.to_string(),
            })
        }
        Err(e) => Err(UsersError::Db(e)),
    }
}

pub async fn find_user_by_email(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
) -> Result<Option<UserRecord>, UsersError> {
    let row: Option<(Uuid, Uuid, String, String, String)> = sqlx::query_as(
        "select id, tenant_id, email, password_hash, role from users where tenant_id = $1 and email = $2",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(id, tenant_id, email, password_hash, role)| {
        role.parse().ok().map(|role| UserRecord {
            id,
            tenant_id,
            email,
            password_hash,
            role,
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let hash = match hash_password("correct horse battery staple") {
            Ok(h) => h,
            Err(e) => panic!("{e}"),
        };
        assert!(verify_password("correct horse battery staple", &hash));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let hash = match hash_password("correct horse battery staple") {
            Ok(h) => h,
            Err(e) => panic!("{e}"),
        };
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn malformed_hash_is_rejected_not_panicked_on() {
        assert!(!verify_password("anything", "not a real argon2 hash"));
    }

    #[test]
    fn same_password_hashes_differently_each_time() {
        // A fresh random salt every call - so two hashes of the same
        // password never match byte-for-byte, even though both verify.
        let a = match hash_password("s3cret") {
            Ok(h) => h,
            Err(e) => panic!("{e}"),
        };
        let b = match hash_password("s3cret") {
            Ok(h) => h,
            Err(e) => panic!("{e}"),
        };
        assert_ne!(a, b);
        assert!(verify_password("s3cret", &a));
        assert!(verify_password("s3cret", &b));
    }

    #[test]
    fn role_round_trips_through_its_string_form() {
        for role in [Role::Admin, Role::Approver, Role::Viewer] {
            let s = role.as_str();
            let parsed: Role = s.parse().unwrap_or_else(|_| panic!("{s} must parse back"));
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn unknown_role_string_is_rejected() {
        assert!("superuser".parse::<Role>().is_err());
    }
}
