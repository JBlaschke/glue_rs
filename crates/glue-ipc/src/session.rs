//! Controller-side connection ledger; no clocks, threads or process ownership.
//!
//! Feed codec-validated messages in pipe order. Record an outgoing message
//! immediately before sending it; a failed send ends the connection. Protocol
//! violations also end the connection. This ledger cannot roll back partially
//! written frames, enforce a timeout, interrupt a runtime or wait for exit.

use crate::{Message, identifier};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    AwaitHello,
    Running,
    Draining,
    Stopped,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("unexpected IPC message: {0}")]
    Unexpected(&'static str),
    #[error("IPC worker component or archive identity differs")]
    Identity,
    #[error("invalid, reused or unknown IPC request ID")]
    RequestId,
    #[error("IPC outstanding-request limit reached")]
    Backpressure,
    #[error("invalid IPC session configuration or message: {0}")]
    Invalid(&'static str),
    #[error("IPC EOF before acknowledged shutdown")]
    UnexpectedEof,
}

/// One component and archive per worker connection. IDs increase strictly,
/// avoiding an unbounded history of completed IDs. Responses may arrive in any
/// order. Pending IDs remain owned until a single terminal response arrives.
pub struct ControllerSession {
    component: String,
    archive_sha256: [u8; 32],
    phase: Phase,
    max_pending: usize,
    last_id: u64,
    pending: BTreeMap<u64, bool>,
}

impl ControllerSession {
    pub fn new(
        component: String,
        archive_sha256: [u8; 32],
        max_pending: usize,
    ) -> Result<Self, SessionError> {
        identifier(&component).map_err(|_| SessionError::Invalid("component"))?;
        if max_pending == 0 || max_pending > 4096 {
            return Err(SessionError::Invalid("max_pending must be 1..4096"));
        }
        Ok(Self {
            component,
            archive_sha256,
            phase: Phase::AwaitHello,
            max_pending,
            last_id: 0,
            pending: BTreeMap::new(),
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn pending_requests(&self) -> usize {
        self.pending.len()
    }

    pub fn cancellation_requested(&self, id: u64) -> Option<bool> {
        self.pending.get(&id).copied()
    }

    /// Check and record a controller message before transport. A local
    /// Backpressure result leaves the ledger unchanged, so a caller may wait
    /// for a terminal result and retry that unsent request. Never retry after
    /// a transport or peer protocol error on the same connection.
    pub fn outgoing(&mut self, message: &Message) -> Result<(), SessionError> {
        match message {
            Message::Request {
                id,
                method,
                timeout_ms,
                ..
            } => {
                if self.phase != Phase::Running {
                    return Err(SessionError::Unexpected(
                        "request before hello or after shutdown",
                    ));
                }
                if *id == 0 || *id <= self.last_id {
                    return Err(SessionError::RequestId);
                }
                identifier(method).map_err(|_| SessionError::Invalid("method"))?;
                if *timeout_ms == Some(0) {
                    return Err(SessionError::Invalid("zero timeout"));
                }
                if self.pending.len() >= self.max_pending {
                    return Err(SessionError::Backpressure);
                }
                self.pending.insert(*id, false);
                self.last_id = *id;
                Ok(())
            }
            Message::Cancel { id } => {
                if !matches!(self.phase, Phase::Running | Phase::Draining) {
                    return Err(SessionError::Unexpected("cancel outside active connection"));
                }
                let pending = self.pending.get_mut(id).ok_or(SessionError::RequestId)?;
                if *pending {
                    return Err(SessionError::Unexpected("duplicate cancellation"));
                }
                *pending = true;
                Ok(())
            }
            Message::Shutdown => {
                if self.phase != Phase::Running {
                    return Err(SessionError::Unexpected(
                        "shutdown outside running connection",
                    ));
                }
                self.phase = Phase::Draining;
                Ok(())
            }
            _ => Err(SessionError::Unexpected(
                "worker message sent by controller",
            )),
        }
    }

    pub fn incoming(&mut self, message: &Message) -> Result<(), SessionError> {
        if self.phase == Phase::AwaitHello {
            let Message::Hello {
                component,
                archive_sha256,
            } = message
            else {
                return Err(SessionError::Unexpected("worker did not begin with hello"));
            };
            if component != &self.component || archive_sha256 != &self.archive_sha256 {
                return Err(SessionError::Identity);
            }
            self.phase = Phase::Running;
            return Ok(());
        }
        match message {
            Message::Response { id, .. } | Message::Error { id, .. } => {
                if !matches!(self.phase, Phase::Running | Phase::Draining) {
                    return Err(SessionError::Unexpected("result after stopped"));
                }
                self.pending.remove(id).ok_or(SessionError::RequestId)?;
                Ok(())
            }
            Message::Stopped => {
                if self.phase != Phase::Draining || !self.pending.is_empty() {
                    return Err(SessionError::Unexpected("stopped before drain completed"));
                }
                self.phase = Phase::Stopped;
                Ok(())
            }
            _ => Err(SessionError::Unexpected(
                "controller message or repeated hello from worker",
            )),
        }
    }

    /// Clean framing EOF still signals worker failure unless Stopped was seen.
    /// A real supervisor must additionally inspect the child process exit.
    pub fn eof(&self) -> Result<(), SessionError> {
        if self.phase == Phase::Stopped {
            Ok(())
        } else {
            Err(SessionError::UnexpectedEof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    fn hello() -> Message {
        Message::Hello {
            component: "python-main".into(),
            archive_sha256: [0xab; 32],
        }
    }

    fn request(id: u64) -> Message {
        Message::Request {
            id,
            method: "app.echo".into(),
            timeout_ms: None,
            args: Value::Null,
        }
    }

    fn response(id: u64) -> Message {
        Message::Response {
            id,
            value: Value::Null,
        }
    }

    fn running(max: usize) -> ControllerSession {
        let mut session = ControllerSession::new("python-main".into(), [0xab; 32], max).unwrap();
        session.incoming(&hello()).unwrap();
        session
    }

    #[test]
    fn hello_binds_component_and_archive_before_requests() {
        let mut session = ControllerSession::new("python-main".into(), [0xab; 32], 2).unwrap();
        assert_eq!(session.phase(), Phase::AwaitHello);
        assert!(session.outgoing(&request(1)).is_err());
        assert!(session.incoming(&response(1)).is_err());
        for wrong in [
            Message::Hello {
                component: "lua-main".into(),
                archive_sha256: [0xab; 32],
            },
            Message::Hello {
                component: "python-main".into(),
                archive_sha256: [0xac; 32],
            },
        ] {
            assert_eq!(session.incoming(&wrong), Err(SessionError::Identity));
            assert_eq!(session.phase(), Phase::AwaitHello);
        }
        session.incoming(&hello()).unwrap();
        assert_eq!(session.phase(), Phase::Running);
        assert!(session.incoming(&hello()).is_err());
    }

    #[test]
    fn bounded_pending_requests_and_unsent_retry() {
        let mut session = running(2);
        session.outgoing(&request(1)).unwrap();
        session.outgoing(&request(3)).unwrap();
        assert_eq!(
            session.outgoing(&request(5)),
            Err(SessionError::Backpressure)
        );
        assert_eq!(session.pending_requests(), 2);
        session.incoming(&response(3)).unwrap();
        session.outgoing(&request(5)).unwrap();
        session.incoming(&response(1)).unwrap();
        session.incoming(&response(5)).unwrap();
        assert_eq!(session.pending_requests(), 0);
    }

    #[test]
    fn ids_cannot_be_reused_after_completion_or_overflow() {
        let mut session = running(2);
        assert_eq!(session.outgoing(&request(0)), Err(SessionError::RequestId));
        session.outgoing(&request(2)).unwrap();
        assert_eq!(session.outgoing(&request(1)), Err(SessionError::RequestId));
        assert_eq!(session.outgoing(&request(2)), Err(SessionError::RequestId));
        session.incoming(&response(2)).unwrap();
        assert_eq!(session.outgoing(&request(2)), Err(SessionError::RequestId));
        session.outgoing(&request(u64::MAX)).unwrap();
        session.incoming(&response(u64::MAX)).unwrap();
        assert_eq!(session.outgoing(&request(1)), Err(SessionError::RequestId));
    }

    #[test]
    fn cancellation_retains_slot_until_one_terminal_result() {
        for terminal in [
            response(1),
            Message::Error {
                id: 1,
                code: "cancelled".into(),
                message: "cancelled".into(),
            },
        ] {
            let mut session = running(1);
            session.outgoing(&request(1)).unwrap();
            session.outgoing(&Message::Cancel { id: 1 }).unwrap();
            assert_eq!(session.cancellation_requested(1), Some(true));
            assert_eq!(
                session.outgoing(&request(2)),
                Err(SessionError::Backpressure)
            );
            assert!(session.outgoing(&Message::Cancel { id: 1 }).is_err());
            session.incoming(&terminal).unwrap();
            assert_eq!(session.cancellation_requested(1), None);
            assert_eq!(session.incoming(&terminal), Err(SessionError::RequestId));
            assert_eq!(
                session.outgoing(&Message::Cancel { id: 1 }),
                Err(SessionError::RequestId)
            );
            session.outgoing(&request(2)).unwrap();
        }
    }

    #[test]
    fn rejects_unknown_results_and_wrong_directions() {
        let mut session = running(2);
        assert_eq!(session.incoming(&response(0)), Err(SessionError::RequestId));
        assert_eq!(
            session.incoming(&response(99)),
            Err(SessionError::RequestId)
        );
        assert_eq!(
            session.outgoing(&Message::Cancel { id: 99 }),
            Err(SessionError::RequestId)
        );
        for message in [
            hello(),
            response(1),
            Message::Stopped,
            Message::Error {
                id: 1,
                code: "failed".into(),
                message: "failure".into(),
            },
        ] {
            assert!(session.outgoing(&message).is_err());
        }
        for message in [request(1), Message::Cancel { id: 1 }, Message::Shutdown] {
            assert!(session.incoming(&message).is_err());
        }
    }

    #[test]
    fn shutdown_drains_pending_and_allows_cancellation() {
        let mut session = running(2);
        assert!(session.incoming(&Message::Stopped).is_err());
        session.outgoing(&request(1)).unwrap();
        session.outgoing(&Message::Shutdown).unwrap();
        assert_eq!(session.phase(), Phase::Draining);
        assert!(session.outgoing(&request(2)).is_err());
        assert!(session.outgoing(&Message::Shutdown).is_err());
        assert!(session.incoming(&Message::Stopped).is_err());
        session.outgoing(&Message::Cancel { id: 1 }).unwrap();
        session.incoming(&response(1)).unwrap();
        session.incoming(&Message::Stopped).unwrap();
        assert_eq!(session.phase(), Phase::Stopped);
        assert!(session.outgoing(&request(2)).is_err());
        assert!(session.outgoing(&Message::Cancel { id: 1 }).is_err());
        assert!(session.outgoing(&Message::Shutdown).is_err());
        assert!(session.incoming(&response(1)).is_err());
        assert!(session.incoming(&Message::Stopped).is_err());
        session.eof().unwrap();
    }

    #[test]
    fn eof_before_shutdown_acknowledgement_is_failure() {
        let mut session = ControllerSession::new("python-main".into(), [0xab; 32], 2).unwrap();
        assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
        session.incoming(&hello()).unwrap();
        assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
        session.outgoing(&Message::Shutdown).unwrap();
        assert_eq!(session.eof(), Err(SessionError::UnexpectedEof));
        session.incoming(&Message::Stopped).unwrap();
        assert_eq!(session.eof(), Ok(()));
    }

    #[test]
    fn validates_configuration_and_outgoing_method_timeout() {
        for component in ["", "name with spaces", "not/ascii", "λ"] {
            assert!(ControllerSession::new(component.into(), [0; 32], 1).is_err());
        }
        for max in [0, 4097, usize::MAX] {
            assert!(ControllerSession::new("app".into(), [0; 32], max).is_err());
        }
        let mut session = running(1);
        for message in [
            Message::Request {
                id: 1,
                method: "bad/name".into(),
                timeout_ms: None,
                args: Value::Null,
            },
            Message::Request {
                id: 1,
                method: "good".into(),
                timeout_ms: Some(0),
                args: Value::Null,
            },
        ] {
            assert!(session.outgoing(&message).is_err());
            assert_eq!(session.pending_requests(), 0);
        }
        session.outgoing(&request(1)).unwrap();
    }
}
