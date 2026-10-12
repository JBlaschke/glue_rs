//! Synthetic Rust peer for protocol tests; no language runtime is involved.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::process::ExitCode;

use glue_ipc::{Limits, Message, encode, read_message, write_message};

fn send(output: &mut impl Write, message: &Message) -> Result<(), glue_ipc::Error> {
    write_message(output, message, Limits::default())?;
    output.flush()?;
    Ok(())
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    eprintln!("glue-ipc-peer: synthetic Rust protocol peer");
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    send(
        &mut output,
        &Message::Hello {
            component: "fixture-worker".into(),
            archive_sha256: [0xab; 32],
        },
    )?;
    let mut deferred = BTreeSet::new();
    let mut last_id = 0;
    let mut draining = false;
    loop {
        let message = read_message(&mut input, Limits::default())?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing shutdown"))?;
        match message {
            Message::Request {
                id, method, args, ..
            } if !draining && id > last_id => {
                last_id = id;
                match method.as_str() {
                    "echo" => send(&mut output, &Message::Response { id, value: args })?,
                    "error" => send(
                        &mut output,
                        &Message::Error {
                            id,
                            code: "fixture.failure".into(),
                            message: "intentional fixture error".into(),
                        },
                    )?,
                    "defer" if deferred.len() < 4096 => {
                        deferred.insert(id);
                    }
                    "crash" => {
                        eprintln!("glue-ipc-peer: intentional crash before terminal result");
                        return Ok(17);
                    }
                    "partial-header" | "partial-body" => {
                        let frame =
                            encode(&Message::Response { id, value: args }, Limits::default())?;
                        let end = if method == "partial-header" {
                            5
                        } else {
                            frame.len() - 1
                        };
                        output.write_all(&frame[..end])?;
                        output.flush()?;
                        eprintln!("glue-ipc-peer: intentional crash during {method}");
                        return Ok(17);
                    }
                    _ => send(
                        &mut output,
                        &Message::Error {
                            id,
                            code: "fixture.method".into(),
                            message: "unsupported fixture method or deferred-request limit".into(),
                        },
                    )?,
                }
            }
            Message::Cancel { id } if deferred.remove(&id) => send(
                &mut output,
                &Message::Error {
                    id,
                    code: "cancelled".into(),
                    message: "deferred fixture request cancelled".into(),
                },
            )?,
            Message::Shutdown if !draining => draining = true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected fixture protocol message",
                )
                .into());
            }
        }
        if draining && deferred.is_empty() {
            send(&mut output, &Message::Stopped)?;
            return Ok(0);
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("glue-ipc-peer: {error}");
            ExitCode::FAILURE
        }
    }
}
