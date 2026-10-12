use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use glue_ipc::session::{ControllerSession, Phase, SessionError};
use glue_ipc::{Error, Limits, Message, Value, encode, read_message, write_message};

// A reader thread lets the parent enforce a deadline even when the child stops
// producing bytes. Drop kills/reaps the peer and joins both pipe readers on any
// test failure. Messages written below are small enough to fit in a pipe buffer.
struct Peer {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Result<Option<Message>, Error>>,
    output_reader: Option<JoinHandle<()>>,
    diagnostics_reader: Option<JoinHandle<Vec<u8>>>,
    deadline: Instant,
}

impl Peer {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_glue-ipc-peer"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let mut output = child.stdout.take().unwrap();
        let mut diagnostics = child.stderr.take().unwrap();
        let (sender, frames) = mpsc::channel();
        let output_reader = thread::spawn(move || {
            loop {
                let frame = read_message(&mut output, Limits::default());
                let terminal = !matches!(&frame, Ok(Some(_)));
                if sender.send(frame).is_err() || terminal {
                    break;
                }
            }
        });
        let diagnostics_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            diagnostics.read_to_end(&mut bytes).unwrap();
            bytes
        });
        Self {
            child,
            input,
            frames,
            output_reader: Some(output_reader),
            diagnostics_reader: Some(diagnostics_reader),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn send(&mut self, session: &mut ControllerSession, message: &Message) {
        session.outgoing(message).unwrap();
        let input = self.input.as_mut().unwrap();
        write_message(input, message, Limits::default()).unwrap();
        input.flush().unwrap();
    }

    fn frame(&self) -> Result<Option<Message>, Error> {
        self.frames
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .expect("protocol peer did not produce a frame before the deadline")
    }

    fn receive(&self, session: &mut ControllerSession) -> Message {
        let message = self.frame().unwrap().expect("unexpected framing EOF");
        session.incoming(&message).unwrap();
        message
    }

    fn wait(&mut self) -> ExitStatus {
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < self.deadline,
                "peer did not exit before deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn diagnostics(&mut self) -> String {
        String::from_utf8(self.diagnostics_reader.take().unwrap().join().unwrap()).unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.input.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.output_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.diagnostics_reader.take() {
            let _ = reader.join();
        }
    }
}

fn start() -> (Peer, ControllerSession) {
    let peer = Peer::spawn();
    let mut session = ControllerSession::new("fixture-worker".into(), [0xab; 32], 4).unwrap();
    assert_eq!(
        peer.receive(&mut session),
        Message::Hello {
            component: "fixture-worker".into(),
            archive_sha256: [0xab; 32],
        }
    );
    assert_eq!(session.phase(), Phase::Running);
    (peer, session)
}

fn request(id: u64, method: &str, args: Value) -> Message {
    Message::Request {
        id,
        method: method.into(),
        timeout_ms: Some(5000),
        args,
    }
}

fn stop(peer: &mut Peer, session: &mut ControllerSession) {
    peer.send(session, &Message::Shutdown);
    assert_eq!(peer.receive(session), Message::Stopped);
    assert_eq!(peer.frame().unwrap(), None);
    session.eof().unwrap();
    assert!(peer.wait().success());
    assert!(peer.diagnostics().contains("synthetic Rust protocol peer"));
}

#[test]
fn values_and_error_results_cross_real_pipes_before_acknowledged_shutdown() {
    let (mut peer, mut session) = start();
    let value = Value::Map(BTreeMap::from([
        (
            "values".into(),
            Value::List(vec![
                Value::Null,
                Value::Bool(false),
                Value::Bool(true),
                Value::I64(i64::MIN),
                Value::U64(u64::MAX),
                Value::F64(-0.0),
                Value::String("λ\0source".into()),
                Value::Bytes(vec![0, 255, 128]),
            ]),
        ),
        ("é".into(), Value::Map(BTreeMap::new())),
    ]));
    peer.send(&mut session, &request(1, "echo", value.clone()));
    let response = peer.receive(&mut session);
    assert_eq!(response, Message::Response { id: 1, value });
    let Message::Response {
        value: Value::Map(map),
        ..
    } = response
    else {
        panic!("echo changed the value tag");
    };
    let Value::List(values) = &map["values"] else {
        panic!("echo changed the list tag");
    };
    let Value::F64(number) = values[5] else {
        panic!("echo changed the float tag");
    };
    assert_eq!(number.to_bits(), (-0.0_f64).to_bits());
    peer.send(&mut session, &request(2, "error", Value::Null));
    assert_eq!(
        peer.receive(&mut session),
        Message::Error {
            id: 2,
            code: "fixture.failure".into(),
            message: "intentional fixture error".into(),
        }
    );
    assert_eq!(session.pending_requests(), 0);
    stop(&mut peer, &mut session);
}

#[test]
fn deferred_request_cancellation_drains_after_out_of_order_completion() {
    let (mut peer, mut session) = start();
    peer.send(&mut session, &request(1, "defer", Value::Null));
    peer.send(&mut session, &request(2, "echo", Value::Bool(true)));
    assert_eq!(
        peer.receive(&mut session),
        Message::Response {
            id: 2,
            value: Value::Bool(true)
        }
    );
    assert_eq!(session.pending_requests(), 1);
    peer.send(&mut session, &Message::Shutdown);
    assert_eq!(session.phase(), Phase::Draining);
    peer.send(&mut session, &Message::Cancel { id: 1 });
    assert_eq!(session.cancellation_requested(1), Some(true));
    assert_eq!(
        peer.receive(&mut session),
        Message::Error {
            id: 1,
            code: "cancelled".into(),
            message: "deferred fixture request cancelled".into(),
        }
    );
    assert_eq!(session.pending_requests(), 0);
    assert_eq!(peer.receive(&mut session), Message::Stopped);
    assert_eq!(peer.frame().unwrap(), None);
    session.eof().unwrap();
    assert!(peer.wait().success());
}

#[test]
fn process_crash_can_be_clean_framing_eof_but_incomplete_lifecycle() {
    let (mut peer, mut session) = start();
    peer.send(&mut session, &request(1, "crash", Value::Null));
    assert_eq!(peer.frame().unwrap(), None);
    assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
    assert_eq!(session.pending_requests(), 1);
    assert_eq!(peer.wait().code(), Some(17));
    assert!(
        peer.diagnostics()
            .contains("intentional crash before terminal result")
    );
}

#[test]
fn process_crash_during_header_or_payload_is_truncated_framing() {
    for method in ["partial-header", "partial-body"] {
        let (mut peer, mut session) = start();
        peer.send(
            &mut session,
            &request(1, method, Value::String("partial".into())),
        );
        assert!(matches!(peer.frame(), Err(Error::Truncated)), "{method}");
        assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
        assert_eq!(session.pending_requests(), 1);
        assert_eq!(peer.wait().code(), Some(17));
        assert!(peer.diagnostics().contains("intentional crash during"));
    }
}

#[test]
fn truncated_controller_request_is_rejected_without_stopped_acknowledgement() {
    let (mut peer, session) = start();
    let frame = encode(&request(1, "echo", Value::Null), Limits::default()).unwrap();
    let mut input = peer.input.take().unwrap();
    input.write_all(&frame[..frame.len() - 1]).unwrap();
    drop(input);
    assert_eq!(peer.frame().unwrap(), None);
    assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
    assert!(!peer.wait().success());
    assert!(peer.diagnostics().contains("truncated IPC frame"));
}
