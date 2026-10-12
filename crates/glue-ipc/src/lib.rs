//! Experimental, bounded messages for future launcher-owned runtime workers.
//!
//! This crate neither starts workers nor executes a language runtime. A caller
//! supplies private protocol pipes, handles deadlines and process lifecycle, and
//! closes a connection after a protocol or transport error. Integer tags retain
//! every bit; JavaScript bindings must use BigInt for values outside its exact
//! Number range. Archive hashes identify inputs, without authenticating peers.

mod codec;
pub mod session;

use std::collections::BTreeMap;

pub use codec::{decode, encode, read_message, write_message};

pub const VERSION: u16 = 0;
pub const HEADER_BYTES: usize = 16;
pub const MAGIC: [u8; 8] = *b"GLUEIPC\0";

/// Owned cross-language values. Floats must be finite. Maps use unique UTF-8
/// keys in lexicographic byte order, enforced on the wire as well as in Rust.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

/// Request IDs are nonzero and scoped to one worker connection. A request has
/// exactly one terminal Response or Error, including when cancellation races
/// completion. Timeout and Cancel express intent; they do not enforce it.
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Hello {
        component: String,
        archive_sha256: [u8; 32],
    },
    Request {
        id: u64,
        method: String,
        /// Remaining duration at dispatch, in milliseconds; zero is invalid.
        timeout_ms: Option<u32>,
        args: Value,
    },
    Response {
        id: u64,
        value: Value,
    },
    Error {
        id: u64,
        code: String,
        message: String,
    },
    Cancel {
        id: u64,
    },
    Shutdown,
    /// The worker has finished shutdown and finalization.
    Stopped,
}

/// Per-frame budgets. Callers may lower these defaults, but cannot exceed the
/// absolute validation ceilings. Depth counts the root value as level one;
/// nodes count values (including containers), not map keys or message fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_string_bytes: usize,
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_container_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_string_bytes: 256 * 1024,
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_nodes: 16_384,
            max_container_items: 4096,
        }
    }
}

impl Limits {
    /// Validate budgets before any reads, writes or frame allocation. The frame
    /// bound applies to the payload, excluding the fixed 16-byte header.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_frame_bytes == 0
            || self.max_frame_bytes > 16 * 1024 * 1024
            || self.max_string_bytes == 0
            || self.max_string_bytes > self.max_frame_bytes
            || self.max_bytes == 0
            || self.max_bytes > self.max_frame_bytes
            || self.max_depth == 0
            || self.max_depth > 64
            || self.max_nodes == 0
            || self.max_nodes > 65_536
            || self.max_container_items == 0
            || self.max_container_items > 16_384
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid IPC limits")]
    InvalidLimits,
    #[error("invalid IPC frame magic")]
    Magic,
    #[error("unsupported IPC version {0}")]
    Version(u16),
    #[error("unsupported IPC frame flags {0}")]
    Flags(u16),
    #[error("IPC limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid IPC encoding: {0}")]
    Invalid(&'static str),
    #[error("truncated IPC frame")]
    Truncated,
    #[error("IPC transport: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(Error::Invalid("identifier"));
    }
    Ok(())
}
