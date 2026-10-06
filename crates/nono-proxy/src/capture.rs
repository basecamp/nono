//! Command-backed credential capture interface.
//!
//! The proxy owns the trigger (`cmd://` route needs a credential), while the
//! CLI/supervisor owns command execution. This module defines the narrow
//! boundary between those crates.

use zeroize::Zeroizing;

/// Request context for a command-backed credential capture.
#[derive(Debug, Clone)]
pub struct CredentialCaptureRequest {
    /// Logical credential name from `cmd://<name>`.
    pub credential_name: String,
    /// Route prefix that triggered capture.
    pub route_id: String,
    /// Upstream host for the request.
    pub request_host: String,
    /// Upstream request path.
    pub request_path: String,
    /// HTTP method that triggered capture.
    pub request_method: String,
    /// Stable supervisor/proxy session identifier.
    pub session_id: String,
    /// Cache scope derived from request context.
    pub cache_scope: String,
}

/// Metadata about a capture attempt. Secret stdout is intentionally excluded.
#[derive(Debug, Clone, Default)]
pub struct CredentialCaptureMetadata {
    pub cache_action: String,
    pub command: Option<String>,
    pub argv: Vec<String>,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub stdout_bytes: Option<usize>,
    pub stderr_redacted: Option<String>,
    pub cache_scope: Option<String>,
    pub output_format: Option<String>,
    pub header_names: Vec<String>,
    pub stdin_mode: Option<String>,
    pub interactive: Option<bool>,
}

/// Captured material that can be injected into the upstream request.
#[derive(Debug, Clone)]
pub enum CredentialCaptureMaterial {
    /// A single credential value, formatted later by the route config.
    Secret(Zeroizing<String>),
    /// Fully materialized headers produced by the capture command.
    Headers(Vec<(String, Zeroizing<String>)>),
}

impl CredentialCaptureMaterial {
    /// Whether `other` is the same captured material: the same secret, or the
    /// same headers in the same order. Used to tell a stale credential from
    /// one captured since, without exposing either value.
    #[must_use]
    pub fn same_material(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Secret(a), Self::Secret(b)) => a.as_bytes() == b.as_bytes(),
            (Self::Headers(a), Self::Headers(b)) => {
                a.len() == b.len()
                    && a.iter().zip(b.iter()).all(|((an, av), (bn, bv))| {
                        an.eq_ignore_ascii_case(bn) && av.as_bytes() == bv.as_bytes()
                    })
            }
            _ => false,
        }
    }
}

/// Result of a capture attempt.
#[derive(Debug, Clone)]
pub struct CredentialCaptureResponse {
    pub material: CredentialCaptureMaterial,
    pub metadata: CredentialCaptureMetadata,
}

/// Error returned by a capture backend. It contains only redacted diagnostics.
#[derive(Debug, Clone)]
pub struct CredentialCaptureError {
    pub reason: String,
    pub metadata: Box<CredentialCaptureMetadata>,
}

impl CredentialCaptureError {
    pub fn new(reason: String, metadata: CredentialCaptureMetadata) -> Self {
        Self {
            reason,
            metadata: Box::new(metadata),
        }
    }
}

impl std::fmt::Display for CredentialCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for CredentialCaptureError {}

/// Supervisor-provided backend for command-backed proxy credentials.
pub trait CredentialCaptureBackend: Send + Sync + std::fmt::Debug {
    fn capture(
        &self,
        request: CredentialCaptureRequest,
    ) -> std::result::Result<CredentialCaptureResponse, CredentialCaptureError>;

    /// The upstream rejected a request (HTTP 401) that carried `material`,
    /// captured for `request`. A backend that caches captures should forget
    /// its cached entry for that request, so the next request runs the
    /// capture command again, but only while that entry still holds the same
    /// `material`: a concurrent request may already have captured a newer
    /// credential, which a late 401 for the old one must not evict.
    ///
    /// Returns whether a cached entry was evicted. The default caches
    /// nothing and evicts nothing.
    fn invalidate(
        &self,
        _request: &CredentialCaptureRequest,
        _material: &CredentialCaptureMaterial,
    ) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> CredentialCaptureMaterial {
        CredentialCaptureMaterial::Secret(Zeroizing::new(value.to_string()))
    }

    fn headers(pairs: &[(&str, &str)]) -> CredentialCaptureMaterial {
        CredentialCaptureMaterial::Headers(
            pairs
                .iter()
                .map(|(n, v)| ((*n).to_string(), Zeroizing::new((*v).to_string())))
                .collect(),
        )
    }

    #[test]
    fn same_material_compares_secrets_and_headers() {
        assert!(secret("a").same_material(&secret("a")));
        assert!(!secret("a").same_material(&secret("b")));
        assert!(
            headers(&[("Authorization", "Bearer a")])
                .same_material(&headers(&[("authorization", "Bearer a")]))
        );
        assert!(
            !headers(&[("Authorization", "Bearer a")])
                .same_material(&headers(&[("Authorization", "Bearer b")]))
        );
        assert!(
            !headers(&[("Authorization", "Bearer a")])
                .same_material(&headers(&[("Authorization", "Bearer a"), ("X-Extra", "1")]))
        );
        assert!(!secret("a").same_material(&headers(&[("Authorization", "a")])));
    }
}
