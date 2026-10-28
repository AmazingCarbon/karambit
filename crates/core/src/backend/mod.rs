//! Backend contract and explicit adapter registry (no built-in adapters).
pub mod fake;
pub mod service;
pub use service::*;
mod registry;
mod types;
pub use registry::*;
use std::{fmt, time::Duration};
pub use types::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError {
    RateLimited { retry_after: Duration },
    NotFound,
    AuthExpired,
    NeedsHuman,
    Unsupported,
    Transient,
    Timeout,
    Cancelled,
    Denied,
    InvalidRef,
    InvalidConfig,
    InvalidResponse,
    TtlExceeded,
    Indeterminate,
    BindingChanged,
    AuditUnavailable,
    DeliveryRefused,
}
impl BackendError {
    pub fn rate_limited(retry_after: Duration) -> Self {
        Self::RateLimited {
            retry_after: retry_after.clamp(Duration::from_secs(1), Duration::from_secs(300)),
        }
    }
    /// Normalize untrusted adapter retry hints before scheduling a retry.
    pub fn bounded(self) -> Self {
        match self {
            Self::RateLimited { retry_after } => Self::rate_limited(retry_after),
            other => other,
        }
    }
}
impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RateLimited { .. } => "Backend rate limited; try later",
            Self::NotFound => "Source or reference not found",
            Self::AuthExpired => "Backend login expired; authenticate again",
            Self::NeedsHuman => "Human approval required",
            Self::Unsupported => "Operation unsupported by this source",
            Self::Transient => "Backend temporarily unavailable",
            Self::Timeout => "Backend request timed out",
            Self::Cancelled => "Request cancelled",
            Self::Denied => "Access denied",
            Self::InvalidRef => "Invalid reference",
            Self::InvalidConfig => "Invalid source configuration",
            Self::InvalidResponse => "Invalid backend response",
            Self::TtlExceeded => "Backend credential lifetime exceeds limit",
            Self::Indeterminate => {
                "Issuance outcome unknown; credential may remain active until TTL"
            }
            Self::BindingChanged => "Source or grant changed; obtain new approval",
            Self::AuditUnavailable => {
                "Audit unavailable; operation refused before any upstream call"
            }
            Self::DeliveryRefused => "Audit unavailable; value delivery refused",
        })
    }
}
impl std::error::Error for BackendError {}
pub trait HumanPrompt: Send + Sync {
    fn approve_login(&self, source: &str) -> BResult<()>;
}
pub trait SecretBackend: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    fn parse_ref(&self, native: &str) -> BResult<NativeRef>; // offline
    fn resolve_kind(&self, r: &NativeRef) -> BResult<ResolveKind>; // offline
    fn auth_status(&self) -> AuthState; // RAM observation, no network
    fn authenticate(&self, _c: &CallContext<'_>, _ui: &dyn HumanPrompt) -> BResult<AuthUpdate> {
        Err(BackendError::Unsupported)
    }
    fn refresh_auth(&self, _c: &CallContext<'_>) -> BResult<AuthUpdate> {
        Err(BackendError::Unsupported)
    }
    /// Effect-aware: `effect` is set whenever upstream may have issued
    /// anything, including on `Err` (C-40a). Never `BResult<Bundle>` alone.
    fn resolve(&self, c: &CallContext<'_>, r: &NativeRef, o: &ResolveOpts) -> Resolved;
    fn metadata(&self, _c: &CallContext<'_>, _r: &NativeRef) -> BResult<Meta> {
        Err(BackendError::Unsupported)
    }
    fn list(&self, _c: &CallContext<'_>, _prefix: &str, _page: Option<&str>) -> BResult<Page> {
        Err(BackendError::Unsupported)
    }
    fn renew(
        &self,
        _c: &CallContext<'_>,
        _l: &UpstreamLease,
        _increment: Duration,
    ) -> BResult<UpstreamLease> {
        Err(BackendError::Unsupported)
    }
    /// Revoke by upstream lease ID only (C-40a): works for `Known` and
    /// `KnownId` alike; never needs fabricated TTL/expiry fields.
    fn revoke(&self, _c: &CallContext<'_>, _lease_id: &LeaseId) -> BResult<()> {
        Err(BackendError::Unsupported)
    }
    fn health(&self, _c: &CallContext<'_>) -> BResult<Health> {
        Err(BackendError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_errors_and_rate_limit() {
        for (error, text) in [
            (
                BackendError::RateLimited {
                    retry_after: Duration::ZERO,
                },
                "Backend rate limited; try later",
            ),
            (BackendError::NotFound, "Source or reference not found"),
            (
                BackendError::AuthExpired,
                "Backend login expired; authenticate again",
            ),
            (BackendError::NeedsHuman, "Human approval required"),
            (
                BackendError::Unsupported,
                "Operation unsupported by this source",
            ),
            (BackendError::Transient, "Backend temporarily unavailable"),
            (BackendError::Timeout, "Backend request timed out"),
            (BackendError::Cancelled, "Request cancelled"),
            (BackendError::Denied, "Access denied"),
            (BackendError::InvalidRef, "Invalid reference"),
            (BackendError::InvalidConfig, "Invalid source configuration"),
            (BackendError::InvalidResponse, "Invalid backend response"),
            (
                BackendError::TtlExceeded,
                "Backend credential lifetime exceeds limit",
            ),
            (
                BackendError::Indeterminate,
                "Issuance outcome unknown; credential may remain active until TTL",
            ),
            (
                BackendError::BindingChanged,
                "Source or grant changed; obtain new approval",
            ),
            (
                BackendError::AuditUnavailable,
                "Audit unavailable; operation refused before any upstream call",
            ),
            (
                BackendError::DeliveryRefused,
                "Audit unavailable; value delivery refused",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        for (input, expected) in [(0, 1), (1, 1), (42, 42), (301, 300)] {
            assert_eq!(
                BackendError::rate_limited(Duration::from_secs(input)),
                BackendError::RateLimited {
                    retry_after: Duration::from_secs(expected)
                }
            );
        }
    }
}
