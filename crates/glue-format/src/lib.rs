//! Provisional, validated contracts for a glue archive.
//!
//! Schema zero is an implementation contract, not a compatibility or loader claim.

mod archive;
mod manifest;
mod path;

pub use archive::{
    ARCHIVE_MAGIC, ARCHIVE_VERSION, Archive, ArchiveEntry, ArchiveError, ArchiveLimits,
    LOCATOR_SIZE, write_archive,
};
pub use manifest::*;
pub use path::{
    MAX_RESOURCE_DEPTH, MAX_RESOURCE_METADATA_BYTES, MAX_RESOURCE_NODES, ResourcePath,
    validate_resource_paths,
};

use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Errors in declarative archive metadata. Validation never executes a payload.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported manifest schema {0}; this build accepts schema {SCHEMA_VERSION}")]
    UnsupportedSchemaVersion(u32),
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid resource path {path:?}: {reason}")]
    InvalidResourcePath { path: String, reason: String },
    #[error("invalid SHA-256 digest {0:?}; expected 64 lowercase hexadecimal characters")]
    InvalidDigest(String),
}

/// SHA-256 of the bytes supplied, encoded as lowercase hexadecimal.
///
/// A source artifact digest is not interchangeable with a resource payload digest.
pub fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut result = String::with_capacity(64);
    for byte in hash {
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

pub(crate) fn validate_digest(value: &str) -> Result<(), FormatError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FormatError::InvalidDigest(value.to_owned()));
    }
    Ok(())
}
