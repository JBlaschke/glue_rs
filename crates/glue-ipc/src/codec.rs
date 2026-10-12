use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::{Error, HEADER_BYTES, Limits, MAGIC, Message, VERSION, Value, identifier};

/// Encode one complete frame. Validation finishes before transport I/O begins.
pub fn encode(message: &Message, limits: Limits) -> Result<Vec<u8>, Error> {
    limits.validate()?;
    let mut encoder = Encoder {
        bytes: vec![0; HEADER_BYTES],
        limits,
        nodes: 0,
    };
    encoder.message(message)?;
    let length = (encoder.bytes.len() - HEADER_BYTES) as u32;
    encoder.bytes[..8].copy_from_slice(&MAGIC);
    encoder.bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    encoder.bytes[12..16].copy_from_slice(&length.to_le_bytes());
    Ok(encoder.bytes)
}

/// Decode exactly one frame, rejecting both truncated and trailing input.
pub fn decode(frame: &[u8], limits: Limits) -> Result<Message, Error> {
    limits.validate()?;
    let header = frame.get(..HEADER_BYTES).ok_or(Error::Truncated)?;
    let length = payload_length(header, limits)?;
    let end = HEADER_BYTES + length;
    if frame.len() < end {
        return Err(Error::Truncated);
    }
    if frame.len() != end {
        return Err(Error::Invalid("trailing frame bytes"));
    }
    decode_payload(&frame[HEADER_BYTES..end], limits)
}

/// Read a single frame. Only EOF before its first byte is a clean end of stream.
/// A bad frame leaves connection recovery to the caller, which should close it.
pub fn read_message<R: Read + ?Sized>(
    reader: &mut R,
    limits: Limits,
) -> Result<Option<Message>, Error> {
    limits.validate()?;
    let mut header = [0; HEADER_BYTES];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    }
    read_exact(reader, &mut header[1..])?;
    let length = payload_length(&header, limits)?;
    let mut payload = vec![0; length];
    read_exact(reader, &mut payload)?;
    decode_payload(&payload, limits).map(Some)
}

/// Validate and write one frame without implicitly flushing the transport.
pub fn write_message<W: Write + ?Sized>(
    writer: &mut W,
    message: &Message,
    limits: Limits,
) -> Result<(), Error> {
    let frame = encode(message, limits)?;
    writer.write_all(&frame)?;
    Ok(())
}

fn read_exact<R: Read + ?Sized>(reader: &mut R, bytes: &mut [u8]) -> Result<(), Error> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Truncated
        } else {
            Error::Io(error)
        }
    })
}

fn payload_length(header: &[u8], limits: Limits) -> Result<usize, Error> {
    if header[..8] != MAGIC {
        return Err(Error::Magic);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != VERSION {
        return Err(Error::Version(version));
    }
    let flags = u16::from_le_bytes([header[10], header[11]]);
    if flags != 0 {
        return Err(Error::Flags(flags));
    }
    let length = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if length == 0 {
        return Err(Error::Invalid("empty payload"));
    }
    if length > limits.max_frame_bytes {
        return Err(Error::Limit("frame bytes"));
    }
    Ok(length)
}

struct Encoder {
    bytes: Vec<u8>,
    limits: Limits,
    nodes: usize,
}

impl Encoder {
    fn room(&self, amount: usize) -> Result<(), Error> {
        if amount > self.limits.max_frame_bytes - (self.bytes.len() - HEADER_BYTES) {
            return Err(Error::Limit("frame bytes"));
        }
        Ok(())
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.room(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.put(&[byte])
    }

    fn string(&mut self, string: &str) -> Result<(), Error> {
        if string.len() > self.limits.max_string_bytes {
            return Err(Error::Limit("string bytes"));
        }
        self.room(4 + string.len())?;
        self.put(&(string.len() as u32).to_le_bytes())?;
        self.put(string.as_bytes())
    }

    fn identifier(&mut self, string: &str) -> Result<(), Error> {
        identifier(string)?;
        self.string(string)
    }

    fn id(&mut self, id: u64) -> Result<(), Error> {
        if id == 0 {
            return Err(Error::Invalid("zero request id"));
        }
        self.put(&id.to_le_bytes())
    }

    fn message(&mut self, message: &Message) -> Result<(), Error> {
        match message {
            Message::Hello {
                component,
                archive_sha256,
            } => {
                self.byte(0)?;
                self.identifier(component)?;
                self.put(archive_sha256)
            }
            Message::Request {
                id,
                method,
                timeout_ms,
                args,
            } => {
                self.byte(1)?;
                self.id(*id)?;
                self.identifier(method)?;
                match timeout_ms {
                    None => self.byte(0)?,
                    Some(0) => return Err(Error::Invalid("zero timeout")),
                    Some(timeout) => {
                        self.byte(1)?;
                        self.put(&timeout.to_le_bytes())?;
                    }
                }
                self.value(args, 1)
            }
            Message::Response { id, value } => {
                self.byte(2)?;
                self.id(*id)?;
                self.value(value, 1)
            }
            Message::Error { id, code, message } => {
                self.byte(3)?;
                self.id(*id)?;
                self.identifier(code)?;
                self.string(message)
            }
            Message::Cancel { id } => {
                self.byte(4)?;
                self.id(*id)
            }
            Message::Shutdown => self.byte(5),
            Message::Stopped => self.byte(6),
        }
    }

    fn container(&mut self, count: usize, minimum_item_bytes: usize) -> Result<(), Error> {
        if count > self.limits.max_container_items {
            return Err(Error::Limit("container items"));
        }
        if count > self.limits.max_nodes - self.nodes {
            return Err(Error::Limit("value nodes"));
        }
        self.room(4 + count * minimum_item_bytes)?;
        self.put(&(count as u32).to_le_bytes())
    }

    fn value(&mut self, value: &Value, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_depth {
            return Err(Error::Limit("value depth"));
        }
        if self.nodes == self.limits.max_nodes {
            return Err(Error::Limit("value nodes"));
        }
        self.nodes += 1;
        match value {
            Value::Null => self.byte(0),
            Value::Bool(false) => self.byte(1),
            Value::Bool(true) => self.byte(2),
            Value::I64(integer) => {
                self.byte(3)?;
                self.put(&integer.to_le_bytes())
            }
            Value::U64(integer) => {
                self.byte(4)?;
                self.put(&integer.to_le_bytes())
            }
            Value::F64(float) => {
                if !float.is_finite() {
                    return Err(Error::Invalid("non-finite float"));
                }
                self.byte(5)?;
                self.put(&float.to_le_bytes())
            }
            Value::String(string) => {
                self.byte(6)?;
                self.string(string)
            }
            Value::Bytes(bytes) => {
                if bytes.len() > self.limits.max_bytes {
                    return Err(Error::Limit("byte string bytes"));
                }
                self.room(5 + bytes.len())?;
                self.byte(7)?;
                self.put(&(bytes.len() as u32).to_le_bytes())?;
                self.put(bytes)
            }
            Value::List(values) => {
                self.byte(8)?;
                self.container(values.len(), 1)?;
                for value in values {
                    self.value(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Map(values) => {
                self.byte(9)?;
                self.container(values.len(), 5)?;
                for (key, value) in values {
                    self.string(key)?;
                    self.value(value, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

fn decode_payload(payload: &[u8], limits: Limits) -> Result<Message, Error> {
    let mut decoder = Decoder {
        remaining: payload,
        limits,
        nodes: 0,
    };
    let message = decoder.message()?;
    if !decoder.remaining.is_empty() {
        return Err(Error::Invalid("trailing payload bytes"));
    }
    Ok(message)
}

struct Decoder<'a> {
    remaining: &'a [u8],
    limits: Limits,
    nodes: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let bytes = self.remaining.get(..count).ok_or(Error::Truncated)?;
        self.remaining = &self.remaining[count..];
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut result = [0; N];
        result.copy_from_slice(self.take(N)?);
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn length(&mut self) -> Result<usize, Error> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }

    fn string_slice(&mut self) -> Result<&'a str, Error> {
        let length = self.length()?;
        if length > self.limits.max_string_bytes {
            return Err(Error::Limit("string bytes"));
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| Error::Invalid("UTF-8 string"))
    }

    fn string(&mut self) -> Result<String, Error> {
        Ok(self.string_slice()?.to_owned())
    }

    fn identifier(&mut self) -> Result<String, Error> {
        let string = self.string_slice()?;
        identifier(string)?;
        Ok(string.to_owned())
    }

    fn id(&mut self) -> Result<u64, Error> {
        let id = u64::from_le_bytes(self.array()?);
        if id == 0 {
            return Err(Error::Invalid("zero request id"));
        }
        Ok(id)
    }

    fn message(&mut self) -> Result<Message, Error> {
        match self.byte()? {
            0 => Ok(Message::Hello {
                component: self.identifier()?,
                archive_sha256: self.array()?,
            }),
            1 => {
                let id = self.id()?;
                let method = self.identifier()?;
                let timeout_ms = match self.byte()? {
                    0 => None,
                    1 => {
                        let timeout = u32::from_le_bytes(self.array()?);
                        if timeout == 0 {
                            return Err(Error::Invalid("zero timeout"));
                        }
                        Some(timeout)
                    }
                    _ => return Err(Error::Invalid("timeout tag")),
                };
                Ok(Message::Request {
                    id,
                    method,
                    timeout_ms,
                    args: self.value(1)?,
                })
            }
            2 => Ok(Message::Response {
                id: self.id()?,
                value: self.value(1)?,
            }),
            3 => Ok(Message::Error {
                id: self.id()?,
                code: self.identifier()?,
                message: self.string()?,
            }),
            4 => Ok(Message::Cancel { id: self.id()? }),
            5 => Ok(Message::Shutdown),
            6 => Ok(Message::Stopped),
            _ => Err(Error::Invalid("message tag")),
        }
    }

    fn container(&mut self, minimum_item_bytes: usize) -> Result<usize, Error> {
        let count = self.length()?;
        if count > self.limits.max_container_items {
            return Err(Error::Limit("container items"));
        }
        if count > self.limits.max_nodes - self.nodes {
            return Err(Error::Limit("value nodes"));
        }
        if count > self.remaining.len() / minimum_item_bytes {
            return Err(Error::Truncated);
        }
        Ok(count)
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::Limit("value depth"));
        }
        if self.nodes == self.limits.max_nodes {
            return Err(Error::Limit("value nodes"));
        }
        self.nodes += 1;
        match self.byte()? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(false)),
            2 => Ok(Value::Bool(true)),
            3 => Ok(Value::I64(i64::from_le_bytes(self.array()?))),
            4 => Ok(Value::U64(u64::from_le_bytes(self.array()?))),
            5 => {
                let float = f64::from_le_bytes(self.array()?);
                if !float.is_finite() {
                    return Err(Error::Invalid("non-finite float"));
                }
                Ok(Value::F64(float))
            }
            6 => Ok(Value::String(self.string()?)),
            7 => {
                let length = self.length()?;
                if length > self.limits.max_bytes {
                    return Err(Error::Limit("byte string bytes"));
                }
                Ok(Value::Bytes(self.take(length)?.to_vec()))
            }
            8 => {
                let count = self.container(1)?;
                let mut values = Vec::new();
                for _ in 0..count {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::List(values))
            }
            9 => {
                let count = self.container(5)?;
                let mut values: BTreeMap<String, Value> = BTreeMap::new();
                for _ in 0..count {
                    let key = self.string_slice()?;
                    if values
                        .last_key_value()
                        .is_some_and(|(previous, _)| previous.as_bytes() >= key.as_bytes())
                    {
                        return Err(Error::Invalid("map key order"));
                    }
                    let value = self.value(depth + 1)?;
                    values.insert(key.to_owned(), value);
                }
                Ok(Value::Map(values))
            }
            _ => Err(Error::Invalid("value tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::from(MAGIC);
        frame.extend_from_slice(&VERSION.to_le_bytes());
        frame.extend_from_slice(&0_u16.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn integer_extremes_and_negative_zero_preserve_their_bits() {
        for value in [Value::I64(i64::MIN), Value::U64(u64::MAX)] {
            let message = Message::Response { id: 1, value };
            assert_eq!(
                decode(
                    &encode(&message, Limits::default()).unwrap(),
                    Limits::default()
                )
                .unwrap(),
                message
            );
        }
        let message = Message::Response {
            id: 1,
            value: Value::F64(-0.0),
        };
        let Message::Response {
            value: Value::F64(float),
            ..
        } = decode(
            &encode(&message, Limits::default()).unwrap(),
            Limits::default(),
        )
        .unwrap()
        else {
            panic!("expected float response")
        };
        assert_eq!(float.to_bits(), (-0.0_f64).to_bits());
    }

    #[test]
    fn malformed_map_order_and_duplicate_keys_are_rejected() {
        for keys in [*b"ba", *b"aa"] {
            let mut payload = vec![2];
            payload.extend_from_slice(&1_u64.to_le_bytes());
            payload.push(9);
            payload.extend_from_slice(&2_u32.to_le_bytes());
            for key in keys {
                payload.extend_from_slice(&1_u32.to_le_bytes());
                payload.extend_from_slice(&[key, 0]);
            }
            assert!(matches!(
                decode(&frame(&payload), Limits::default()),
                Err(Error::Invalid("map key order"))
            ));
        }
    }

    #[test]
    fn root_depth_and_container_nodes_are_counted() {
        let value = Value::List(vec![Value::Null]);
        let message = Message::Response { id: 1, value };
        let bytes = encode(&message, Limits::default()).unwrap();
        for limits in [
            Limits {
                max_depth: 1,
                ..Limits::default()
            },
            Limits {
                max_nodes: 1,
                ..Limits::default()
            },
        ] {
            assert!(matches!(encode(&message, limits), Err(Error::Limit(_))));
            assert!(matches!(decode(&bytes, limits), Err(Error::Limit(_))));
        }
        let exact = Limits {
            max_depth: 2,
            max_nodes: 2,
            ..Limits::default()
        };
        assert_eq!(decode(&bytes, exact).unwrap(), message);
    }

    #[test]
    fn concatenated_stream_frames_are_consumed_one_at_a_time() {
        let mut bytes = encode(&Message::Shutdown, Limits::default()).unwrap();
        bytes.extend(encode(&Message::Stopped, Limits::default()).unwrap());
        let mut input = bytes.as_slice();
        assert_eq!(
            read_message(&mut input, Limits::default()).unwrap(),
            Some(Message::Shutdown)
        );
        assert_eq!(
            read_message(&mut input, Limits::default()).unwrap(),
            Some(Message::Stopped)
        );
        assert_eq!(read_message(&mut input, Limits::default()).unwrap(), None);
        assert!(matches!(
            decode(&bytes, Limits::default()),
            Err(Error::Invalid("trailing frame bytes"))
        ));
    }

    #[test]
    fn all_partial_frames_are_truncated() {
        let bytes = encode(&Message::Cancel { id: 1 }, Limits::default()).unwrap();
        for length in 1..bytes.len() {
            assert!(matches!(
                read_message(&mut &bytes[..length], Limits::default()),
                Err(Error::Truncated)
            ));
        }
    }

    #[test]
    fn header_rejection_does_not_read_body() {
        let mut bytes = encode(&Message::Shutdown, Limits::default()).unwrap();
        bytes[10] = 1;
        let mut input = bytes.as_slice();
        assert!(matches!(
            read_message(&mut input, Limits::default()),
            Err(Error::Flags(1))
        ));
        assert_eq!(input, &[5]);
    }

    #[test]
    fn invalid_messages_do_not_write_any_transport_bytes() {
        let message = Message::Response {
            id: 1,
            value: Value::F64(f64::NAN),
        };
        let mut output = Vec::new();
        assert!(matches!(
            write_message(&mut output, &message, Limits::default()),
            Err(Error::Invalid("non-finite float"))
        ));
        assert!(output.is_empty());
    }
}
