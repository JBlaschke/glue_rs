//! Private, bounded owned replies for the C-only Lua boundary.
//!
//! This module never sees a Lua state or calls a Lua API. Top-level values have
//! depth one; table keys and values increase the depth by one. The C decoder
//! uses the same limits and wire tags. Raw reply ownership lives in `bridge`.

use crate::bridge;

pub(crate) const MAX_RESULTS: usize = 16;
pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MAX_REPLY_BYTES: usize = 128 * 1024 * 1024;

const SUCCESS: libc::c_int = 0;
const ERROR: libc::c_int = 1;
#[cfg(test)]
const PANIC: libc::c_int = 2;

/// Values copied to Lua only after the Rust callback has returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    Nil,
    Boolean(bool),
    Integer(i64),
    /// Binary bytes; strings need not be UTF-8 and may contain NUL.
    String(Vec<u8>),
    /// Ordered key/value pairs. Only integer and string keys are accepted.
    Table(Vec<(Value, Value)>),
}

impl Value {
    pub(crate) fn string(bytes: impl AsRef<[u8]>) -> Self {
        Self::String(bytes.as_ref().to_vec())
    }
}

/// Encode a result count followed by the private little-endian value format.
///
/// Validate the complete reply before reserving its output buffer. Filling the
/// buffer then requires no further allocation. The byte limit includes framing.
pub(crate) fn encode(values: &[Value]) -> Result<Vec<u8>, String> {
    encode_with_byte_limit(values, MAX_REPLY_BYTES)
}

fn encode_with_byte_limit(values: &[Value], byte_limit: usize) -> Result<Vec<u8>, String> {
    if values.len() > MAX_RESULTS {
        return Err(format!("callback reply exceeds {MAX_RESULTS} results"));
    }
    let mut length = checked_length(0, 4, byte_limit)?;
    for value in values {
        length = checked_length(length, value_length(value, 1, byte_limit)?, byte_limit)?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "cannot allocate callback reply buffer".to_owned())?;
    // Counts and lengths are checked before these narrowing conversions.
    bytes.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        write_value(&mut bytes, value);
    }
    debug_assert_eq!(bytes.len(), length);
    Ok(bytes)
}

fn value_length(value: &Value, depth: usize, byte_limit: usize) -> Result<usize, String> {
    if depth > MAX_DEPTH {
        return Err(format!("callback reply exceeds depth {MAX_DEPTH}"));
    }
    match value {
        Value::Nil => checked_length(0, 1, byte_limit),
        Value::Boolean(_) => checked_length(0, 2, byte_limit),
        Value::Integer(_) => checked_length(0, 9, byte_limit),
        Value::String(bytes) => {
            u32::try_from(bytes.len())
                .map_err(|_| "callback string exceeds u32 length".to_owned())?;
            checked_length(5, bytes.len(), byte_limit)
        }
        Value::Table(entries) => {
            u32::try_from(entries.len())
                .map_err(|_| "callback table exceeds u32 entry count".to_owned())?;
            let mut length = checked_length(0, 5, byte_limit)?;
            for (key, value) in entries {
                if !matches!(key, Value::Integer(_) | Value::String(_)) {
                    return Err("callback table keys must be integers or strings".to_owned());
                }
                length = checked_length(
                    length,
                    value_length(key, depth + 1, byte_limit)?,
                    byte_limit,
                )?;
                length = checked_length(
                    length,
                    value_length(value, depth + 1, byte_limit)?,
                    byte_limit,
                )?;
            }
            Ok(length)
        }
    }
}

fn checked_length(current: usize, additional: usize, limit: usize) -> Result<usize, String> {
    current
        .checked_add(additional)
        .filter(|length| *length <= limit)
        .ok_or_else(|| format!("callback reply exceeds {limit} bytes"))
}

/// Fill only after `value_length` has validated the complete immutable tree.
fn write_value(bytes: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Nil => bytes.push(0),
        Value::Boolean(value) => bytes.extend_from_slice(&[1, u8::from(*value)]),
        Value::Integer(value) => {
            bytes.push(2);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Value::String(value) => {
            bytes.push(3);
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value);
        }
        Value::Table(entries) => {
            bytes.push(4);
            bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            for (key, value) in entries {
                write_value(bytes, key);
                write_value(bytes, value);
            }
        }
    }
}

/// Reply bytes remain owned until transferred into the bridge's stable cookie.
pub(crate) struct OwnedReply {
    status: libc::c_int,
    bytes: Vec<u8>,
}

impl OwnedReply {
    /// Encoder failures become ordinary callback errors, never partial values.
    pub(crate) fn success(values: &[Value]) -> Self {
        match encode(values) {
            Ok(bytes) => Self::from_bytes(SUCCESS, bytes),
            Err(message) => Self::error(message),
        }
    }

    pub(crate) fn error(message: impl Into<String>) -> Self {
        let message = message.into();
        let bytes = if message.len() <= MAX_REPLY_BYTES {
            message.into_bytes()
        } else {
            b"callback error exceeds reply byte limit".to_vec()
        };
        Self::from_bytes(ERROR, bytes)
    }

    #[cfg(test)]
    pub(crate) fn panic() -> Self {
        Self::from_bytes(PANIC, b"archive callback panicked".to_vec())
    }

    fn from_bytes(status: libc::c_int, bytes: Vec<u8>) -> Self {
        Self { status, bytes }
    }

    pub(crate) fn into_reply(self) -> bridge::Reply {
        bridge::Reply::owned(self.status, self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_tags_and_binary_strings_match_the_wire_contract() {
        let actual = encode(&[
            Value::Nil,
            Value::Boolean(true),
            Value::Integer(-1),
            Value::String(vec![0, 255]),
            Value::Table(vec![]),
        ])
        .unwrap();
        let expected = vec![
            5, 0, 0, 0, // Result count.
            0, // Nil.
            1, 1, // True.
            2, 255, 255, 255, 255, 255, 255, 255, 255, // -1.
            3, 2, 0, 0, 0, 0, 255, // Two binary string bytes.
            4, 0, 0, 0, 0, // Empty table.
        ];
        assert_eq!(actual, expected);
        assert_eq!(
            encode(&[Value::Boolean(false)]).unwrap(),
            [1, 0, 0, 0, 1, 0]
        );
        assert_eq!(encode(&[]).unwrap(), [0, 0, 0, 0]);
    }

    #[test]
    fn nested_tables_preserve_key_value_order_and_integer_edges() {
        let actual = encode(&[Value::Table(vec![
            (Value::Integer(i64::MIN), Value::Integer(i64::MAX)),
            (Value::string(b"\0key"), Value::Table(vec![])),
        ])])
        .unwrap();
        let mut expected = vec![1, 0, 0, 0, 4, 2, 0, 0, 0, 2];
        expected.extend_from_slice(&i64::MIN.to_le_bytes());
        expected.push(2);
        expected.extend_from_slice(&i64::MAX.to_le_bytes());
        expected.extend_from_slice(&[3, 4, 0, 0, 0, 0, b'k', b'e', b'y', 4, 0, 0, 0, 0]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_table_keys_and_too_many_results_fail_without_a_partial_reply() {
        for key in [Value::Nil, Value::Boolean(false), Value::Table(vec![])] {
            assert!(
                encode(&[Value::Table(vec![(key, Value::Integer(1))])])
                    .unwrap_err()
                    .contains("keys")
            );
        }
        assert!(encode(&vec![Value::Nil; MAX_RESULTS]).is_ok());
        let invalid = vec![Value::Nil; MAX_RESULTS + 1];
        assert!(encode(&invalid).unwrap_err().contains("results"));
        let reply = OwnedReply::success(&invalid);
        assert_eq!(reply.status, ERROR);
        assert!(String::from_utf8(reply.bytes).unwrap().contains("results"));
    }

    fn nested_value(depth: usize) -> Value {
        let mut value = Value::Nil;
        for _ in 1..depth {
            value = Value::Table(vec![(Value::Integer(1), value)]);
        }
        value
    }

    #[test]
    fn depth_limit_counts_top_level_values_as_depth_one() {
        assert!(encode(&[nested_value(MAX_DEPTH)]).is_ok());
        assert!(
            encode(&[nested_value(MAX_DEPTH + 1)])
                .unwrap_err()
                .contains("depth")
        );
    }

    #[test]
    fn byte_budget_includes_framing_and_length_arithmetic_is_checked() {
        let values = [Value::string(b"abc")];
        assert_eq!(encode_with_byte_limit(&values, 12).unwrap().len(), 12);
        assert!(
            encode_with_byte_limit(&values, 11)
                .unwrap_err()
                .contains("bytes")
        );
        assert!(encode_with_byte_limit(&[], 3).is_err());
        assert!(checked_length(usize::MAX, 1, usize::MAX).is_err());
        assert_eq!(MAX_REPLY_BYTES, 128 * 1024 * 1024);
    }

    #[test]
    fn bridge_replies_transfer_owned_bytes_and_release_every_status() {
        let baseline = bridge::owned_reply_count();
        let expected = encode(&[Value::string(b"owned\0binary")]).unwrap();
        let success = OwnedReply::success(&[Value::string(b"owned\0binary")]);
        assert_eq!(success.status, SUCCESS);
        assert_eq!(success.bytes, expected);
        let reply = success.into_reply();
        assert_eq!(reply.status, SUCCESS);
        assert_eq!(reply.len, expected.len());
        assert!(!reply.data.is_null());
        assert!(!reply.cookie.is_null());
        assert_eq!(reply.bytes(), expected);
        assert_eq!(bridge::owned_reply_count(), baseline + 1);
        reply.release_owned();
        assert_eq!(bridge::owned_reply_count(), baseline);

        let error = OwnedReply::error("failure\0diagnostic");
        assert_eq!(error.bytes, b"failure\0diagnostic");
        let reply = error.into_reply();
        assert_eq!(reply.status, ERROR);
        assert_eq!(reply.len, 18);
        assert_eq!(reply.bytes(), b"failure\0diagnostic");
        assert_eq!(bridge::owned_reply_count(), baseline + 1);
        reply.release_owned();
        assert_eq!(bridge::owned_reply_count(), baseline);

        let reply = OwnedReply::panic().into_reply();
        assert_eq!(reply.status, PANIC);
        assert_eq!(reply.len, b"archive callback panicked".len());
        assert_eq!(reply.bytes(), b"archive callback panicked");
        assert_eq!(bridge::owned_reply_count(), baseline + 1);
        reply.release_owned();
        assert_eq!(bridge::owned_reply_count(), baseline);
    }
}
