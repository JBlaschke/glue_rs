use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};

use glue_ipc::{
    Error, HEADER_BYTES, Limits, Message, Value, decode, encode, read_message, write_message,
};

// These vectors construct the specified wire format without using the codec.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"GLUEIPC\0\0\0\0\0".to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn string(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = (bytes.len() as u32).to_le_bytes().to_vec();
    encoded.extend_from_slice(bytes);
    encoded
}

fn response(value: &[u8]) -> Vec<u8> {
    let mut payload = vec![2, 1, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(value);
    frame(&payload)
}

fn assert_vector(message: Message, payload: &[u8]) {
    let expected = frame(payload);
    assert_eq!(encode(&message, Limits::default()).unwrap(), expected);
    assert_eq!(decode(&expected, Limits::default()).unwrap(), message);
}

fn assert_invalid(bytes: &[u8]) {
    assert!(matches!(
        decode(bytes, Limits::default()),
        Err(Error::Invalid(_))
    ));
}

fn assert_limit(bytes: &[u8], limits: Limits) {
    assert!(matches!(decode(bytes, limits), Err(Error::Limit(_))));
}

#[test]
fn fixed_header_and_control_messages_have_independent_golden_vectors() {
    assert_eq!(HEADER_BYTES, 16);
    assert_eq!(
        encode(&Message::Shutdown, Limits::default()).unwrap(),
        b"GLUEIPC\0\0\0\0\0\x01\0\0\0\x05"
    );
    assert_vector(Message::Stopped, &[6]);
    assert_vector(
        Message::Cancel {
            id: 0x0807_0605_0403_0201,
        },
        &[4, 1, 2, 3, 4, 5, 6, 7, 8],
    );
    let mut hello = vec![0, 3, 0, 0, 0, b'a', b'.', b'1'];
    hello.extend_from_slice(&[0x5a; 32]);
    assert_vector(
        Message::Hello {
            component: "a.1".into(),
            archive_sha256: [0x5a; 32],
        },
        &hello,
    );
}

#[test]
fn request_response_and_error_have_independent_golden_vectors() {
    assert_vector(
        Message::Request {
            id: 0x0807_0605_0403_0201,
            method: "echo".into(),
            timeout_ms: None,
            args: Value::Null,
        },
        &[
            1, 1, 2, 3, 4, 5, 6, 7, 8, 4, 0, 0, 0, b'e', b'c', b'h', b'o', 0, 0,
        ],
    );
    assert_vector(
        Message::Request {
            id: 1,
            method: "x".into(),
            timeout_ms: Some(0x0403_0201),
            args: Value::Bool(true),
        },
        &[
            1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, b'x', 1, 1, 2, 3, 4, 2,
        ],
    );
    assert_vector(
        Message::Response {
            id: u64::MAX,
            value: Value::Bool(false),
        },
        &[2, 255, 255, 255, 255, 255, 255, 255, 255, 1],
    );
    assert_vector(
        Message::Error {
            id: 1,
            code: "oops".into(),
            message: "é".into(),
        },
        &[
            3, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, b'o', b'o', b'p', b's', 2, 0, 0, 0, 0xc3, 0xa9,
        ],
    );
}

#[test]
fn signed_unsigned_extrema_and_negative_zero_retain_their_bits() {
    for (value, wire) in [
        (Value::I64(i64::MIN), vec![3, 0, 0, 0, 0, 0, 0, 0, 128]),
        (
            Value::I64(i64::MAX),
            vec![3, 255, 255, 255, 255, 255, 255, 255, 127],
        ),
        (
            Value::I64(-1),
            vec![3, 255, 255, 255, 255, 255, 255, 255, 255],
        ),
        (Value::U64(0), vec![4, 0, 0, 0, 0, 0, 0, 0, 0]),
        (
            Value::U64(u64::MAX),
            vec![4, 255, 255, 255, 255, 255, 255, 255, 255],
        ),
        (Value::F64(-0.0), vec![5, 0, 0, 0, 0, 0, 0, 0, 128]),
    ] {
        let expected = response(&wire);
        let message = Message::Response { id: 1, value };
        assert_eq!(encode(&message, Limits::default()).unwrap(), expected);
        let decoded = decode(&expected, Limits::default()).unwrap();
        assert_eq!(decoded, message);
        if let Message::Response {
            value: Value::F64(number),
            ..
        } = decoded
        {
            assert_eq!(number.to_bits(), (-0.0_f64).to_bits());
        }
    }
}

#[test]
fn nested_utf8_bytes_and_canonical_maps_have_an_independent_vector() {
    let value = Value::Map(BTreeMap::from([
        (
            "z".into(),
            Value::List(vec![Value::Null, Value::Bool(false), Value::Bool(true)]),
        ),
        ("é".into(), Value::Bytes(vec![0, 0xff, 0x80])),
        ("a".into(), Value::String("λ\0".into())),
    ]));
    let wire = [
        9, 3, 0, 0, 0, 1, 0, 0, 0, b'a', 6, 3, 0, 0, 0, 0xce, 0xbb, 0, 1, 0, 0, 0, b'z', 8, 3, 0,
        0, 0, 0, 1, 2, 2, 0, 0, 0, 0xc3, 0xa9, 7, 3, 0, 0, 0, 0, 0xff, 0x80,
    ];
    assert_eq!(
        encode(
            &Message::Response {
                id: 1,
                value: value.clone()
            },
            Limits::default()
        )
        .unwrap(),
        response(&wire)
    );
    assert_eq!(
        decode(&response(&wire), Limits::default()).unwrap(),
        Message::Response { id: 1, value }
    );
    for value in [
        Value::List(vec![]),
        Value::Map(BTreeMap::new()),
        Value::String(String::new()),
        Value::Bytes(vec![]),
    ] {
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
}

#[test]
fn invalid_frame_headers_and_trailing_data_are_rejected() {
    let original = frame(&[5]);
    let mut bad_magic = original.clone();
    bad_magic[0] = b'x';
    assert!(matches!(
        decode(&bad_magic, Limits::default()),
        Err(Error::Magic)
    ));
    let mut bad_version = original.clone();
    bad_version[8..10].copy_from_slice(&1_u16.to_le_bytes());
    assert!(matches!(
        decode(&bad_version, Limits::default()),
        Err(Error::Version(1))
    ));
    let mut bad_flags = original.clone();
    bad_flags[10..12].copy_from_slice(&0x8000_u16.to_le_bytes());
    assert!(matches!(
        decode(&bad_flags, Limits::default()),
        Err(Error::Flags(0x8000))
    ));
    let mut trailing = original.clone();
    trailing.push(0);
    assert_invalid(&trailing);
    assert_invalid(&frame(&[5, 0]));
    assert!(decode(&frame(&[]), Limits::default()).is_err());
    assert_invalid(&frame(&[255]));
    assert_invalid(&response(&[255]));
}

#[test]
fn every_truncated_prefix_is_an_error_and_only_empty_stream_is_clean_eof() {
    let bytes = encode(
        &Message::Response {
            id: 1,
            value: Value::String("complete".into()),
        },
        Limits::default(),
    )
    .unwrap();
    for length in 0..bytes.len() {
        assert!(
            matches!(
                decode(&bytes[..length], Limits::default()),
                Err(Error::Truncated)
            ),
            "decode prefix {length}"
        );
        let result = read_message(&mut Cursor::new(&bytes[..length]), Limits::default());
        if length == 0 {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(
                matches!(result, Err(Error::Truncated)),
                "stream prefix {length}"
            );
        }
    }
    let mut concatenated = bytes.clone();
    concatenated.extend_from_slice(&frame(&[5]));
    let mut reader = Cursor::new(concatenated);
    assert!(
        read_message(&mut reader, Limits::default())
            .unwrap()
            .is_some()
    );
    assert_eq!(
        read_message(&mut reader, Limits::default()).unwrap(),
        Some(Message::Shutdown)
    );
    assert_eq!(read_message(&mut reader, Limits::default()).unwrap(), None);
}

#[test]
fn malformed_utf8_nonfinite_floats_and_timeout_markers_are_rejected() {
    assert_invalid(&response(&[6, 1, 0, 0, 0, 0xff]));
    for bits in [
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        f64::NAN.to_bits(),
    ] {
        let mut wire = vec![5];
        wire.extend_from_slice(&bits.to_le_bytes());
        assert_invalid(&response(&wire));
        assert!(matches!(
            encode(
                &Message::Response {
                    id: 1,
                    value: Value::F64(f64::from_bits(bits))
                },
                Limits::default()
            ),
            Err(Error::Invalid(_))
        ));
    }
    let request = [1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, b'x'];
    let mut unknown_marker = request.to_vec();
    unknown_marker.extend_from_slice(&[2, 0]);
    assert_invalid(&frame(&unknown_marker));
    let mut zero_timeout = request.to_vec();
    zero_timeout.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    assert_invalid(&frame(&zero_timeout));
    assert!(matches!(
        encode(
            &Message::Request {
                id: 1,
                method: "x".into(),
                timeout_ms: Some(0),
                args: Value::Null
            },
            Limits::default()
        ),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn all_request_ids_and_identifier_fields_are_validated() {
    let messages = [
        Message::Request {
            id: 0,
            method: "x".into(),
            timeout_ms: None,
            args: Value::Null,
        },
        Message::Response {
            id: 0,
            value: Value::Null,
        },
        Message::Error {
            id: 0,
            code: "x".into(),
            message: String::new(),
        },
        Message::Cancel { id: 0 },
    ];
    for message in messages {
        assert!(matches!(
            encode(&message, Limits::default()),
            Err(Error::Invalid(_))
        ));
    }
    for tag in [1, 2, 3, 4] {
        let mut payload = vec![tag, 0, 0, 0, 0, 0, 0, 0, 0];
        match tag {
            1 => payload.extend_from_slice(&[1, 0, 0, 0, b'x', 0, 0]),
            2 => payload.push(0),
            3 => payload.extend_from_slice(&[1, 0, 0, 0, b'x', 0, 0, 0, 0]),
            _ => {}
        }
        assert_invalid(&frame(&payload));
    }
    for identifier in [
        "".to_owned(),
        "x y".to_owned(),
        "λ".to_owned(),
        "a".repeat(129),
    ] {
        for message in [
            Message::Hello {
                component: identifier.clone(),
                archive_sha256: [0; 32],
            },
            Message::Request {
                id: 1,
                method: identifier.clone(),
                timeout_ms: None,
                args: Value::Null,
            },
            Message::Error {
                id: 1,
                code: identifier.clone(),
                message: String::new(),
            },
        ] {
            assert!(matches!(
                encode(&message, Limits::default()),
                Err(Error::Invalid(_))
            ));
        }
        let mut hello = vec![0];
        hello.extend_from_slice(&string(identifier.as_bytes()));
        hello.extend_from_slice(&[0; 32]);
        assert_invalid(&frame(&hello));
    }
    let message = Message::Hello {
        component: "a".repeat(128),
        archive_sha256: [0; 32],
    };
    assert_eq!(
        decode(
            &encode(&message, Limits::default()).unwrap(),
            Limits::default()
        )
        .unwrap(),
        message
    );
}

#[test]
fn duplicate_and_out_of_order_map_keys_are_rejected() {
    for keys in [*b"aa", *b"za"] {
        let mut wire = vec![9, 2, 0, 0, 0];
        for key in keys {
            wire.extend_from_slice(&[1, 0, 0, 0, key, 0]);
        }
        assert_invalid(&response(&wire));
    }
    assert_invalid(&response(&[9, 1, 0, 0, 0, 1, 0, 0, 0, 0xff, 0]));
}

#[test]
fn declared_lengths_and_counts_are_bounded_before_contents_are_read() {
    for tag in [6, 7] {
        assert_limit(&response(&[tag, 255, 255, 255, 255]), Limits::default());
    }
    for tag in [8, 9] {
        assert_limit(&response(&[tag, 1, 16, 0, 0]), Limits::default());
        assert_limit(&response(&[tag, 255, 255, 255, 255]), Limits::default());
    }
    let limits = Limits {
        max_string_bytes: 3,
        max_bytes: 3,
        max_container_items: 2,
        ..Limits::default()
    };
    for value in [
        Value::String("four".into()),
        Value::Bytes(vec![0; 4]),
        Value::List(vec![Value::Null; 3]),
        Value::Map(BTreeMap::from([
            ("a".into(), Value::Null),
            ("b".into(), Value::Null),
            ("c".into(), Value::Null),
        ])),
    ] {
        let message = Message::Response { id: 1, value };
        let unrestricted = encode(&message, Limits::default()).unwrap();
        assert_limit(&unrestricted, limits);
        assert!(matches!(encode(&message, limits), Err(Error::Limit(_))));
    }
    let message = Message::Response {
        id: 1,
        value: Value::List(vec![
            Value::String("abc".into()),
            Value::Bytes(vec![0, 1, 2]),
        ]),
    };
    assert_eq!(
        decode(&encode(&message, limits).unwrap(), limits).unwrap(),
        message
    );
}

#[test]
fn depth_and_node_budgets_count_root_values_and_containers() {
    let nested = Message::Response {
        id: 1,
        value: Value::List(vec![Value::List(vec![Value::Null])]),
    };
    let exact = Limits {
        max_depth: 3,
        max_nodes: 3,
        ..Limits::default()
    };
    let bytes = encode(&nested, exact).unwrap();
    assert_eq!(decode(&bytes, exact).unwrap(), nested);
    for limits in [
        Limits {
            max_depth: 2,
            ..exact
        },
        Limits {
            max_nodes: 2,
            ..exact
        },
    ] {
        assert_limit(&bytes, limits);
        assert!(matches!(encode(&nested, limits), Err(Error::Limit(_))));
    }
    let scalar = Message::Response {
        id: 1,
        value: Value::Null,
    };
    let one = Limits {
        max_depth: 1,
        max_nodes: 1,
        ..Limits::default()
    };
    assert_eq!(decode(&encode(&scalar, one).unwrap(), one).unwrap(), scalar);
    // Keys and message fields do not consume value nodes.
    let map = Message::Response {
        id: 1,
        value: Value::Map(BTreeMap::from([("one".into(), Value::Null)])),
    };
    let two = Limits {
        max_depth: 2,
        max_nodes: 2,
        ..Limits::default()
    };
    assert_eq!(decode(&encode(&map, two).unwrap(), two).unwrap(), map);
}

#[test]
fn payload_limit_includes_message_fields_but_excludes_header() {
    let exact = Limits {
        max_frame_bytes: 1,
        max_string_bytes: 1,
        max_bytes: 1,
        ..Limits::default()
    };
    assert_eq!(encode(&Message::Shutdown, exact).unwrap(), frame(&[5]));
    assert_eq!(decode(&frame(&[5]), exact).unwrap(), Message::Shutdown);
    assert_limit(&frame(&[5, 0]), exact);
    assert!(encode(&Message::Stopped, exact).is_ok());
    assert!(matches!(
        encode(&Message::Cancel { id: 1 }, exact),
        Err(Error::Limit(_))
    ));
}

struct FragmentedReader {
    bytes: Cursor<Vec<u8>>,
    interrupt: bool,
}

impl Read for FragmentedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let count = output.len().min(1);
        self.bytes.read(&mut output[..count])
    }
}

#[derive(Default)]
struct FragmentedWriter {
    bytes: Vec<u8>,
    interrupt: bool,
    flushes: usize,
}

impl Write for FragmentedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let count = bytes.len().min(1);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn one_byte_transport_fragments_and_interrupted_calls_preserve_messages() {
    let message = Message::Response {
        id: u64::MAX,
        value: Value::String("λ fragment".into()),
    };
    let expected = encode(&message, Limits::default()).unwrap();
    let mut writer = FragmentedWriter::default();
    write_message(&mut writer, &message, Limits::default()).unwrap();
    assert_eq!(writer.bytes, expected);
    assert_eq!(writer.flushes, 0, "flushing belongs to the transport owner");
    let mut reader = FragmentedReader {
        bytes: Cursor::new(expected),
        interrupt: false,
    };
    assert_eq!(
        read_message(&mut reader, Limits::default()).unwrap(),
        Some(message)
    );
    assert_eq!(read_message(&mut reader, Limits::default()).unwrap(), None);
}

struct ForbiddenIo;

impl Read for ForbiddenIo {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("validation must precede transport reads");
    }
}

impl Write for ForbiddenIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("validation must precede transport writes");
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("codec does not flush");
    }
}

#[test]
fn invalid_limits_are_rejected_before_any_allocation_or_transport_io() {
    let defaults = Limits::default();
    let invalid = [
        Limits {
            max_frame_bytes: 0,
            ..defaults
        },
        Limits {
            max_frame_bytes: 16 * 1024 * 1024 + 1,
            ..defaults
        },
        Limits {
            max_string_bytes: 0,
            ..defaults
        },
        Limits {
            max_string_bytes: defaults.max_frame_bytes + 1,
            ..defaults
        },
        Limits {
            max_bytes: 0,
            ..defaults
        },
        Limits {
            max_bytes: defaults.max_frame_bytes + 1,
            ..defaults
        },
        Limits {
            max_depth: 0,
            ..defaults
        },
        Limits {
            max_depth: 65,
            ..defaults
        },
        Limits {
            max_nodes: 0,
            ..defaults
        },
        Limits {
            max_nodes: 65_537,
            ..defaults
        },
        Limits {
            max_container_items: 0,
            ..defaults
        },
        Limits {
            max_container_items: 16_385,
            ..defaults
        },
    ];
    for limits in invalid {
        assert!(matches!(
            encode(&Message::Shutdown, limits),
            Err(Error::InvalidLimits)
        ));
        assert!(matches!(decode(&[], limits), Err(Error::InvalidLimits)));
        assert!(matches!(
            read_message(&mut ForbiddenIo, limits),
            Err(Error::InvalidLimits)
        ));
        assert!(matches!(
            write_message(&mut ForbiddenIo, &Message::Shutdown, limits),
            Err(Error::InvalidLimits)
        ));
    }
}

#[test]
fn invalid_messages_are_fully_validated_before_writing_any_bytes() {
    for message in [
        Message::Cancel { id: 0 },
        Message::Hello {
            component: "bad name".into(),
            archive_sha256: [0; 32],
        },
        Message::Response {
            id: 1,
            value: Value::F64(f64::NAN),
        },
        Message::Response {
            id: 1,
            value: Value::List(vec![Value::Null; 4097]),
        },
    ] {
        assert!(write_message(&mut ForbiddenIo, &message, Limits::default()).is_err());
    }
}

struct HeaderOnly {
    header: Cursor<Vec<u8>>,
}

impl Read for HeaderOnly {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(
            (self.header.position() as usize) < HEADER_BYTES,
            "oversized header must be rejected before reading a body"
        );
        self.header.read(bytes)
    }
}

#[test]
fn oversized_and_invalid_headers_do_not_read_payload_bytes() {
    let mut oversize = frame(&[5]);
    oversize[12..16].copy_from_slice(&(1024 * 1024 + 1_u32).to_le_bytes());
    oversize.truncate(HEADER_BYTES);
    let mut reader = HeaderOnly {
        header: Cursor::new(oversize),
    };
    assert!(matches!(
        read_message(&mut reader, Limits::default()),
        Err(Error::Limit(_))
    ));
    for index in [0, 8, 10] {
        let mut header = frame(&[5]);
        header[index] = 255;
        header.truncate(HEADER_BYTES);
        let mut reader = HeaderOnly {
            header: Cursor::new(header),
        };
        assert!(read_message(&mut reader, Limits::default()).is_err());
    }
}

struct FailingReader {
    bytes: Vec<u8>,
    position: usize,
    fail_at: usize,
}

impl Read for FailingReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.position == self.fail_at {
            return Err(io::Error::other("synthetic read failure"));
        }
        let count = output
            .len()
            .min(self.fail_at - self.position)
            .min(self.bytes.len() - self.position);
        output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

struct FailingWriter {
    zero: bool,
}

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        if self.zero {
            Ok(0)
        } else {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("codec does not flush");
    }
}

#[test]
fn transport_failures_and_zero_length_writes_are_returned() {
    for fail_at in [0, 5, HEADER_BYTES] {
        let mut reader = FailingReader {
            bytes: frame(&[5]),
            position: 0,
            fail_at,
        };
        assert!(
            matches!(read_message(&mut reader, Limits::default()), Err(Error::Io(error)) if error.kind() == io::ErrorKind::Other)
        );
    }
    assert!(
        matches!(write_message(&mut FailingWriter { zero: false }, &Message::Shutdown, Limits::default()), Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(
        matches!(write_message(&mut FailingWriter { zero: true }, &Message::Shutdown, Limits::default()), Err(Error::Io(error)) if error.kind() == io::ErrorKind::WriteZero)
    );
}
