//! Version-specific process helpers and explicit installation discovery.
//!
//! A packager can discover either family even when it links the other family.
//! Helpers are selected from supplied directories, never from execution PATH.

use glue_format::{
    Archive, DeliveryMode, InputIdentity, LuaNumber, RuntimeAbi, RuntimeDescriptor,
    RuntimeImplementation, RuntimeLaunchSpec, RuntimeProvider, RuntimeVersion, SourcePin, digest,
};
use glue_resources::Resources;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};

/// Versioned helper command/descriptor protocol.
pub const HELPER_PROTOCOL: u32 = 1;
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LuaFamily {
    #[serde(rename = "5.4")]
    Lua54,
    #[serde(rename = "5.5")]
    Lua55,
}

impl LuaFamily {
    pub fn executable_name(self) -> String {
        format!(
            "{}{}",
            match self {
                Self::Lua54 => "glue-lua54",
                Self::Lua55 => "glue-lua55",
            },
            std::env::consts::EXE_SUFFIX
        )
    }

    pub fn version(self) -> RuntimeVersion {
        let (minor, patch) = match self {
            Self::Lua54 => (4, 9),
            Self::Lua55 => (5, 1),
        };
        RuntimeVersion {
            major: 5,
            minor,
            patch,
        }
    }
}

impl FromStr for LuaFamily {
    type Err = HelperError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "5.4" => Ok(Self::Lua54),
            "5.5" => Ok(Self::Lua55),
            _ => Err(HelperError::Invalid(format!(
                "unsupported Lua family {value:?}; select 5.4 or 5.5"
            ))),
        }
    }
}

/// Exact linked runtime identity, queried without opening an application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperDescriptor {
    pub protocol: u32,
    pub implementation: String,
    pub provider: String,
    pub family: LuaFamily,
    pub version: RuntimeVersion,
    pub target: String,
    pub integer_bits: u8,
    pub number: LuaNumber,
    pub build_id: String,
    pub source: SourcePin,
    pub error_boundary: String,
    pub exports: BTreeSet<String>,
}

impl HelperDescriptor {
    /// Shared compact-manifest identity for this helper executable.
    pub fn runtime_descriptor(
        &self,
        executable: String,
        identity: InputIdentity,
    ) -> RuntimeDescriptor {
        RuntimeDescriptor {
            implementation: RuntimeImplementation::Lua,
            version: self.source.release.clone(),
            target: self.target.clone(),
            abi: RuntimeAbi::Lua {
                version: self.version,
                integer_bits: self.integer_bits,
                number: self.number,
            },
            provider: RuntimeProvider::Bundled,
            inputs: BTreeMap::from([(executable.clone(), identity)]),
            executable,
            requirements: BTreeSet::new(),
        }
    }

    pub fn launch_spec(&self, executable: String) -> RuntimeLaunchSpec {
        RuntimeLaunchSpec {
            executable,
            args: vec!["run".to_owned(), "{archive}".to_owned()],
            environment: BTreeMap::new(),
            clear_environment: false,
        }
    }

    pub fn validate(&self, family: LuaFamily, target: &str) -> Result<(), HelperError> {
        let version = family.version();
        let expected_build = format!(
            "glue-lua5{}-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64",
            version.minor
        );
        if self.protocol != HELPER_PROTOCOL
            || self.implementation != "lua"
            || self.provider != "glue-linked-helper"
            || self.family != family
            || self.version != version
            || self.target != target
            || self.integer_bits != 64
            || self.number != LuaNumber::Float64
            || self.build_id != expected_build
            || self.source != source_for(family)
            || self.error_boundary != "glue-c-boundary-1"
            || !["lua_gettop", "luaL_checkversion_", "luaL_error"]
                .iter()
                .all(|symbol| self.exports.contains(*symbol))
        {
            return Err(HelperError::Invalid(format!(
                "helper descriptor does not match selected {family:?} int64/float64 runtime for {target}"
            )));
        }
        Ok(())
    }
}

fn source_for(family: LuaFamily) -> SourcePin {
    let version = family.version();
    SourcePin {
        release: format!("{}.{}.{}", version.major, version.minor, version.patch),
        revision: None,
        artifact: "https://static.crates.io/crates/lua-src/lua-src-551.0.2.crate".to_owned(),
        sha256: "d400ffef0e3d4d29287092bdc5a276d0bf468b2c69709d5bab0d469312d9f947".to_owned(),
        variant: format!("lua5{}-static-int64-float64", version.minor),
    }
}

pub fn compiled_descriptor() -> HelperDescriptor {
    let family = if cfg!(feature = "lua55") {
        LuaFamily::Lua55
    } else {
        LuaFamily::Lua54
    };
    HelperDescriptor {
        protocol: HELPER_PROTOCOL,
        implementation: "lua".to_owned(),
        provider: "glue-linked-helper".to_owned(),
        family,
        version: family.version(),
        target: env!("GLUE_LUA_TARGET").to_owned(),
        integer_bits: 64,
        number: LuaNumber::Float64,
        build_id: crate::profile::BUILD_ID.to_owned(),
        source: crate::profile::source_pin(),
        error_boundary: "glue-c-boundary-1".to_owned(),
        exports: include_str!(env!("GLUE_LUA_HELPER_EXPORTS_PATH"))
            .lines()
            .map(str::to_owned)
            .collect(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    #[error("invalid Lua helper: {0}")]
    Invalid(String),
    #[error("Lua helper I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Lua helper descriptor: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct SelectedHelper {
    pub executable: PathBuf,
    pub descriptor: HelperDescriptor,
    pub size: u64,
    pub sha256: String,
}

impl SelectedHelper {
    /// Construct a direct subprocess command; no shell or PATH lookup is used.
    pub fn command(&self, archive: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        command.arg("run").arg(archive);
        command
    }
}

/// Probe a supplied helper with bounded descriptor output. This is a build-time
/// operation: the supplied executable must be trusted by the caller as an input.
pub fn query(executable: &Path) -> Result<HelperDescriptor, HelperError> {
    let mut child = Command::new(executable)
        .arg("--describe")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .expect("piped descriptor output")
        .take(MAX_DESCRIPTOR_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        return Err(HelperError::Invalid("descriptor exceeds 64 KiB".to_owned()));
    }
    if !child.wait()?.success() {
        return Err(HelperError::Invalid("descriptor query failed".to_owned()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Select only from explicit installation directories, in order. The packaging
/// launcher normally passes its own executable directory as its final entry.
/// An incompatible installed helper is an error, not a reason to try PATH.
pub fn discover(
    family: LuaFamily,
    target: &str,
    directories: &[PathBuf],
) -> Result<SelectedHelper, HelperError> {
    for directory in directories {
        let executable = directory.join(family.executable_name());
        if !executable.try_exists()? {
            continue;
        }
        let executable = fs::canonicalize(executable)?;
        let descriptor = query(&executable)?;
        descriptor.validate(family, target)?;
        let bytes = fs::read(&executable)?;
        return Ok(SelectedHelper {
            executable,
            descriptor,
            size: bytes.len() as u64,
            sha256: digest(&bytes),
        });
    }
    Err(HelperError::Invalid(format!(
        "{} is not installed in the supplied helper directories; run scripts/install-lua-helpers.sh",
        family.executable_name()
    )))
}

/// Helper executable entry point. Application paths remain OS strings.
pub fn main_with_args(arguments: impl IntoIterator<Item = OsString>) -> u8 {
    let arguments: Vec<_> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [flag] if flag == "--describe" => match serde_json::to_string(&compiled_descriptor()) {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(error) => fail(error, 1),
        },
        [command, path] if command == "run" => run_archive(Path::new(path), Vec::new()),
        [command, path, separator, arguments @ ..] if command == "run" && separator == "--" => {
            run_archive(
                Path::new(path),
                arguments
                    .iter()
                    .cloned()
                    .map(OsString::into_encoded_bytes)
                    .collect(),
            )
        }
        _ => fail(
            "usage: glue-lua54|glue-lua55 --describe | run ARCHIVE [-- ARGUMENTS...]",
            2,
        ),
    }
}

fn run_archive(path: &Path, arguments: Vec<Vec<u8>>) -> u8 {
    let result = File::open(path)
        .map_err(|error| error.to_string())
        .and_then(|file| Archive::open(file).map_err(|error| error.to_string()));
    let archive = match result {
        Ok(archive) => archive,
        Err(error) => return fail(error, 1),
    };
    let entry = match validate_archive(archive.manifest()) {
        Ok(entry) => entry,
        Err(error) => {
            let status = if matches!(error, crate::profile::CapabilityError::Unsupported(_)) {
                2
            } else {
                1
            };
            return fail(error, status);
        }
    };
    let compact = archive.manifest().distribution.is_some();
    let result = if compact {
        let root = path
            .parent()
            .filter(|root| !root.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        crate::execute_compact(
            Resources::with_default_cache(archive),
            &entry,
            arguments,
            root,
        )
    } else if arguments.is_empty() {
        crate::execute(Resources::with_default_cache(archive), &entry)
    } else {
        return fail("application arguments require a compact Lua archive", 2);
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let status = if error.is_unsupported() { 2 } else { 1 };
            fail(error, status)
        }
    }
}

fn validate_archive(
    manifest: &glue_format::Manifest,
) -> Result<String, crate::profile::CapabilityError> {
    use crate::profile::CapabilityError;
    let Some(distribution) = &manifest.distribution else {
        return crate::profile::validate(manifest);
    };
    let invalid = |message: &str| CapabilityError::Invalid(message.to_owned());
    let descriptor = compiled_descriptor();
    let runtime = &distribution.runtime;
    let expected_abi = RuntimeAbi::Lua {
        version: descriptor.version,
        integer_bits: descriptor.integer_bits,
        number: descriptor.number,
    };
    if runtime.implementation != RuntimeImplementation::Lua
        || runtime.version != descriptor.source.release
        || runtime.abi != expected_abi
        || runtime.target != descriptor.target
        || runtime.provider != RuntimeProvider::Bundled
    {
        return Err(invalid(
            "runtime ABI/version/target differs from selected linked Lua helper",
        ));
    }
    if distribution.delivery != DeliveryMode::Compact {
        return Err(CapabilityError::Unsupported(
            "Lua helper requires compact delivery".to_owned(),
        ));
    }
    Ok(manifest.entrypoint.clone())
}

fn fail(error: impl std::fmt::Display, status: u8) -> u8 {
    eprintln!("{error}");
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_selection_is_independent_of_the_linked_family() {
        assert_eq!("5.4".parse::<LuaFamily>().unwrap(), LuaFamily::Lua54);
        assert_eq!("5.5".parse::<LuaFamily>().unwrap(), LuaFamily::Lua55);
        for value in ["5.1", "5.3", "LuaJIT", "5.4.9", "latest", ""] {
            assert!(value.parse::<LuaFamily>().is_err());
        }
    }

    #[cfg(not(feature = "linux-native"))]
    #[test]
    fn exact_descriptor_round_trips_and_rejects_version_and_numeric_mismatch() {
        let descriptor = compiled_descriptor();
        descriptor
            .validate(descriptor.family, &descriptor.target)
            .unwrap();
        let bytes = serde_json::to_vec(&descriptor).unwrap();
        assert_eq!(
            serde_json::from_slice::<HelperDescriptor>(&bytes).unwrap(),
            descriptor
        );
        for field in [
            "patch", "integer", "number", "target", "source", "boundary", "protocol",
        ] {
            let mut wrong = descriptor.clone();
            match field {
                "patch" => wrong.version.patch += 1,
                "integer" => wrong.integer_bits = 32,
                "number" => wrong.number = LuaNumber::Float32,
                "target" => wrong.target.push_str("-different"),
                "source" => wrong.source.sha256 = "0".repeat(64),
                "boundary" => wrong.error_boundary.push_str("-different"),
                "protocol" => wrong.protocol += 1,
                _ => unreachable!(),
            }
            assert!(
                wrong
                    .validate(descriptor.family, &descriptor.target)
                    .is_err(),
                "{field}"
            );
        }
        let other = if descriptor.family == LuaFamily::Lua54 {
            LuaFamily::Lua55
        } else {
            LuaFamily::Lua54
        };
        assert!(descriptor.validate(other, &descriptor.target).is_err());
    }

    #[test]
    fn empty_explicit_search_does_not_use_path_or_current_directory() {
        assert!(discover(LuaFamily::Lua54, env!("GLUE_LUA_TARGET"), &[]).is_err());
    }
}
