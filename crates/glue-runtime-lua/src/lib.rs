//! Official Lua linked into the launcher, with verified archive source imports.
//!
//! This first execution profile intentionally omits `io`, `os`, and `debug`.
//! `require` searches only `app/?.lua` and `app/?/init.lua`; `loadfile` and
//! `dofile` accept canonical archive keys. `load` accepts source strings only.
//! These restrictions are an initial compatibility profile, not a sandbox or
//! the final policy for applications' ordinary host I/O. The optional
//! `linux-native` profile eagerly loads a verified native closure before Lua
//! starts. The caller must validate provisioning and target compatibility.

pub mod profile;

#[allow(unsafe_code)]
mod bridge;
mod wire;

#[cfg(all(feature = "lua54", feature = "lua55"))]
compile_error!("select exactly one linked Lua profile: lua54 or lua55");
#[cfg(not(any(feature = "lua54", feature = "lua55")))]
compile_error!("select a linked Lua profile: lua54 or lua55");

use glue_format::{Compression, ResourcePath};
use glue_resources::{EntryKind, Metadata, ResourceError, Resources};
use std::io::{Read, Seek};
use wire::{OwnedReply, Value};

/// An archive/resource or protected Lua execution error.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ExecutionError {
    message: String,
    unsupported: bool,
}

impl ExecutionError {
    /// Whether an unavailable capability, rather than a failed execution, was
    /// encountered. CLI callers preserve the existing unsupported status 2.
    pub fn is_unsupported(&self) -> bool {
        self.unsupported
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unsupported: false,
        }
    }

    #[cfg(feature = "linux-native")]
    fn native(error: glue_native::NativeError) -> Self {
        Self {
            unsupported: matches!(error, glue_native::NativeError::Unsupported(_)),
            message: error.to_string(),
        }
    }
}

/// Execute one verified archive source chunk in the restricted linked profile.
///
/// Entry return values are discarded. Errors retain virtual `glue://` source
/// names; no source or asset is materialized as a host file. The private C
/// boundary owns all Lua calls and contains Lua errors before returning to Rust.
pub fn execute<R: Read + Seek>(
    mut resources: Resources<R>,
    entry_point: &str,
) -> Result<(), ExecutionError> {
    ResourcePath::new(entry_point).map_err(|error| ExecutionError::failed(error.to_string()))?;
    let bytes = resources
        .read(entry_point)
        .map_err(|error| ExecutionError::failed(error.to_string()))?;
    let app_id = &resources.manifest().app_id;
    let origin = resource_origin(app_id, entry_point);
    let package_path = format!("glue://{app_id}/app/?.lua;glue://{app_id}/app/?/init.lua");
    #[cfg(feature = "linux-native")]
    let native = if resources.manifest().native_modules.is_empty() {
        None
    } else {
        let exports = include_str!("../native-exports.txt")
            .lines()
            .map(str::to_owned)
            .collect();
        Some(
            glue_native::NativePlan::prepare(&mut resources, &exports)
                .and_then(glue_native::NativePlan::load)
                .map_err(ExecutionError::native)?,
        )
    };
    let mut context = Context {
        resources,
        #[cfg(feature = "linux-native")]
        native,
    };
    bridge::execute(
        move |operation, key| match context.request(operation, key) {
            Ok(values) => OwnedReply::success(&values).into_reply(),
            Err(message) => OwnedReply::error(message).into_reply(),
        },
        include_bytes!("bootstrap.lua"),
        &package_path,
        &bytes,
        &origin,
    )
    .map_err(ExecutionError::failed)
}

// Archive work runs synchronously without a Lua state or Lua API. All borrows
// and Rust temporaries end before the C trampoline constructs Lua values.
struct Context<R: Read + Seek> {
    resources: Resources<R>,
    #[cfg(feature = "linux-native")]
    native: Option<glue_native::NativeManager>,
}

impl<R: Read + Seek> Context<R> {
    fn request(&mut self, operation: u32, key: &[u8]) -> Result<Vec<Value>, String> {
        let key = std::str::from_utf8(key).map_err(|_| "archive key must be UTF-8".to_owned())?;
        match operation {
            1 => {
                let bytes = self
                    .resources
                    .read(key)
                    .map_err(|error| error.to_string())?;
                Ok(vec![Value::String(bytes.to_vec()), self.origin(key)])
            }
            2 => {
                self.resources
                    .stat(key)
                    .map_err(|error| error.to_string())?;
                Ok(vec![self.origin(key)])
            }
            3 => Ok(vec![metadata_value(
                self.resources
                    .stat(key)
                    .map_err(|error| error.to_string())?,
            )?]),
            4 => {
                let entries = self
                    .resources
                    .list(key)
                    .map_err(|error| error.to_string())?;
                let mut rows = Vec::with_capacity(entries.len());
                for (index, entry) in entries.into_iter().enumerate() {
                    let Value::Table(mut row) = metadata_value(entry.metadata)? else {
                        unreachable!()
                    };
                    row.push((string("name"), string(entry.name)));
                    row.push((string("path"), string(entry.path)));
                    let index =
                        i64::try_from(index + 1).map_err(|_| "too many directory entries")?;
                    rows.push((Value::Integer(index), Value::Table(row)));
                }
                Ok(vec![Value::Table(rows)])
            }
            5 => {
                module_candidates(key)?;
                Ok(vec![Value::Boolean(true)])
            }
            6 => {
                let candidates = module_candidates(key)?;
                for path in &candidates {
                    match self.resources.stat(path) {
                        Ok(metadata) if metadata.is_file() => {
                            return Ok(vec![string(path), self.origin(path)]);
                        }
                        Ok(_) | Err(ResourceError::NotFound(_)) => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(vec![
                    Value::Nil,
                    string(format!(
                        "\n\tno archive module {key:?} ({} or {})",
                        candidates[0], candidates[1]
                    )),
                ])
            }
            #[cfg(feature = "linux-native")]
            7 => {
                module_candidates(key)?;
                match self
                    .native
                    .as_ref()
                    .and_then(|manager| manager.by_name(key))
                {
                    Some((resource, initializer)) => Ok(vec![
                        Value::NativeFunction(initializer),
                        self.origin(resource),
                    ]),
                    None => Ok(vec![
                        Value::Nil,
                        string(format!("\n\tno declared native module {key:?}")),
                    ]),
                }
            }
            #[cfg(feature = "linux-native")]
            8 | 9 => {
                ResourcePath::new(key).map_err(|error| error.to_string())?;
                match self
                    .native
                    .as_ref()
                    .and_then(|manager| manager.by_resource(key))
                {
                    Some((symbol, _)) if operation == 9 => Ok(vec![string(symbol)]),
                    Some((_, initializer)) => {
                        Ok(vec![Value::NativeFunction(initializer), self.origin(key)])
                    }
                    None => Ok(vec![
                        Value::Nil,
                        string("resource is not a declared native Lua root"),
                    ]),
                }
            }
            _ => Err("invalid archive operation".to_owned()),
        }
    }

    fn origin(&self, path: &str) -> Value {
        string(resource_origin(&self.resources.manifest().app_id, path))
    }
}

fn string(value: impl AsRef<[u8]>) -> Value {
    Value::string(value)
}

fn metadata_value(metadata: Metadata) -> Result<Value, String> {
    let integer = |value| {
        i64::try_from(value)
            .map(Value::Integer)
            .map_err(|_| "resource metadata exceeds Lua integer range".to_owned())
    };
    Ok(Value::Table(vec![
        (
            string("kind"),
            string(match metadata.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "directory",
            }),
        ),
        (string("size"), integer(metadata.size)?),
        (
            string("compressed_size"),
            integer(metadata.compressed_size)?,
        ),
        (
            string("compression"),
            match metadata.compression {
                Some(Compression::Stored) => string("stored"),
                Some(Compression::Deflate) => string("deflate"),
                None => Value::Nil,
            },
        ),
    ]))
}

fn module_candidates(name: &str) -> Result<[String; 2], String> {
    if name.is_empty()
        || name.len() > 4096
        || name.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
    {
        return Err(format!(
            "invalid archive module name {name:?}; use dot-separated ASCII letters, digits, underscores or hyphens"
        ));
    }
    let stem = name.replace('.', "/");
    let candidates = [format!("app/{stem}.lua"), format!("app/{stem}/init.lua")];
    for path in &candidates {
        ResourcePath::new(path).map_err(|error| error.to_string())?;
    }
    Ok(candidates)
}

fn resource_origin(app_id: &str, path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut origin = format!("glue://{app_id}/");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            origin.push(char::from(byte));
        } else {
            origin.push('%');
            origin.push(char::from(HEX[usize::from(byte >> 4)]));
            origin.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    origin
}
