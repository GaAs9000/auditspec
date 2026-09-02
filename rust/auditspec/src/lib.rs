//! Standalone Rust consumer for AuditSpec Vault and verifier material.

pub mod canonical;
pub mod information_order;
pub mod predicate;
pub mod trust;
pub mod vault;

use std::io;

/// Error returned for malformed, unsafe, or unverifiable AuditSpec material.
#[derive(Debug, thiserror::Error)]
pub enum AuditSpecError {
    #[error("{0}")]
    Invalid(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, AuditSpecError>;

pub(crate) fn invalid(message: impl Into<String>) -> AuditSpecError {
    AuditSpecError::Invalid(message.into())
}
