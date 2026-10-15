//! Revision-one compact distribution contracts. Schema zero retains its original meaning.
use crate::{
    FormatError, Manifest, ResourcePath, RuntimeAbi, digest, validate_digest,
    validate_resource_paths,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Compact,
    Memory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProvider {
    Bundled,
    Host,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeImplementation {
    Lua,
    Cpython,
    Node,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputIdentity {
    pub size: u64,
    pub sha256: String,
}
impl InputIdentity {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            size: bytes.len() as u64,
            sha256: digest(bytes),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDescriptor {
    pub implementation: RuntimeImplementation,
    pub version: String,
    pub target: String,
    pub abi: RuntimeAbi,
    pub provider: RuntimeProvider,
    /// Relative deployed executable, or an explicitly selected absolute host executable.
    pub executable: String,
    pub inputs: BTreeMap<String, InputIdentity>,
    #[serde(default)]
    pub requirements: BTreeSet<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadKind {
    File,
    Symlink { target: String },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadRecord {
    pub size: u64,
    pub sha256: String,
    pub mode: u32,
    pub kind: PayloadKind,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchSpec {
    pub executable: String,
    /// Literal arguments; only {root} and {archive} are substituted, without a shell.
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub clear_environment: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInventory {
    pub roots: BTreeMap<String, String>,
    pub edges: Vec<NativeDependency>,
    pub host_requirements: BTreeSet<String>,
    pub features: BTreeSet<String>,
    pub transformations: Vec<Transformation>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyProvider {
    Runtime,
    Bundled,
    OperatingSystem,
    Host,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDependency {
    pub from: String,
    pub name: String,
    pub provider: DependencyProvider,
    pub resolved: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    pub path: String,
    pub input: InputIdentity,
    pub output: InputIdentity,
    pub edits: Vec<String>,
    pub signing: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionSpec {
    pub delivery: DeliveryMode,
    pub runtime: RuntimeDescriptor,
    pub payloads: BTreeMap<String, PayloadRecord>,
    pub native: NativeInventory,
    pub launch: RuntimeLaunchSpec,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildLock {
    pub revision: u32,
    pub runtime: RuntimeDescriptor,
    pub inputs: BTreeMap<String, InputIdentity>,
    pub transformations: Vec<Transformation>,
    pub options: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SizeAccounting {
    pub archive_bytes: u64,
    pub archived_uncompressed_bytes: u64,
    pub payload_bytes: u64,
    pub deployed_files: u64,
    pub deployed_directories: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionBuildReport {
    pub revision: u32,
    pub runtime: RuntimeDescriptor,
    pub archive: InputIdentity,
    pub payloads: BTreeMap<String, PayloadRecord>,
    pub native: NativeInventory,
    pub sizes: SizeAccounting,
    pub omissions: BTreeMap<String, String>,
    pub limitations: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    MissingInput,
    MissingEntry,
    MissingDependency,
    RuntimeAbiMismatch,
    TargetMismatch,
    UnsupportedCapability,
    UnsupportedMode,
    PathEscape,
    PayloadIntegrity,
    TransformationRequired,
    RuntimeProcessFailure,
    InvalidConfiguration,
    OutputExists,
    ResourceLimit,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message} ({remedy})")]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub message: String,
    pub input: Option<String>,
    pub target: Option<String>,
    pub runtime: Option<String>,
    pub remedy: String,
}
impl Diagnostic {
    pub fn new(
        code: DiagnosticCode,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            input: None,
            target: None,
            runtime: None,
            remedy: remedy.into(),
        }
    }
}

fn invalid(message: impl Into<String>) -> FormatError {
    FormatError::InvalidManifest(message.into())
}
/// Deployed paths have exactly the same canonical spelling rules as archive paths.
pub fn validate_payload_path(path: &str) -> Result<(), FormatError> {
    ResourcePath::new(path).map(|_| ())
}
/// Resolve a relative symlink lexically, rejecting escape before filesystem access.
pub fn resolve_payload_link(path: &str, target: &str) -> Result<String, FormatError> {
    validate_payload_path(path)?;
    if target.is_empty() || target.starts_with('/') || target.contains(['\\', ':', '\0']) {
        return Err(invalid("payload link must be relative"));
    }
    let mut parts: Vec<_> = path.split('/').collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                if parts.pop().is_none() {
                    return Err(invalid("payload link escapes distribution"));
                }
            }
            _ => parts.push(part),
        }
    }
    let result = parts.join("/");
    validate_payload_path(&result)?;
    Ok(result)
}
pub(crate) fn validate_manifest(m: &Manifest) -> Result<(), FormatError> {
    let d = m
        .distribution
        .as_ref()
        .ok_or_else(|| invalid("schema one requires distribution"))?;
    if !m.targets.is_empty()
        || !m.runtimes.is_empty()
        || !m.components.is_empty()
        || !m.native_modules.is_empty()
        || !m.host_imports.is_empty()
    {
        return Err(invalid(
            "schema one uses distribution descriptors, not legacy runtime/component maps",
        ));
    }
    if m.app_id.is_empty() {
        return Err(invalid("app ID is empty"));
    }
    validate_resource_paths(m.resources.keys())?;
    if !m.resources.contains_key(&m.entrypoint) {
        return Err(invalid("entrypoint resource is missing"));
    }
    for r in m.resources.values() {
        validate_digest(&r.sha256)?;
    }
    validate_resource_paths(d.payloads.keys())?;
    for (path, p) in &d.payloads {
        validate_digest(&p.sha256)?;
        if p.mode & !0o777 != 0 {
            return Err(invalid("payload mode must not contain special bits"));
        }
        if ["app.glue", "glue.lock.json", "build-report.json"].contains(&path.as_str()) {
            return Err(invalid("payload collides with generated metadata"));
        }
        if let PayloadKind::Symlink { target } = &p.kind {
            let resolved = resolve_payload_link(path, target)?;
            if !d.payloads.contains_key(&resolved) {
                return Err(invalid("payload symlink target is undeclared"));
            }
            let mut seen = BTreeSet::from([path.clone()]);
            let mut next = resolved;
            loop {
                if !seen.insert(next.clone()) {
                    return Err(invalid("payload symlink cycle"));
                }
                match &d.payloads[&next].kind {
                    PayloadKind::File => break,
                    PayloadKind::Symlink { target } => {
                        next = resolve_payload_link(&next, target)?;
                        if !d.payloads.contains_key(&next) {
                            return Err(invalid("payload symlink target is undeclared"));
                        }
                    }
                }
            }
            if p.size != target.len() as u64 || p.sha256 != digest(target.as_bytes()) {
                return Err(invalid("symlink identity differs from link text"));
            }
        }
    }
    let r = &d.runtime;
    if r.version.is_empty() || r.inputs.is_empty() {
        return Err(invalid("runtime needs exact version and input identities"));
    }
    for identity in r.inputs.values() {
        validate_digest(&identity.sha256)?;
    }
    let expected = match &r.abi {
        RuntimeAbi::Lua {
            version,
            integer_bits: 64,
            number: crate::LuaNumber::Float64,
        } if version.major == 5 && [4, 5].contains(&version.minor) => {
            (RuntimeImplementation::Lua, version)
        }
        RuntimeAbi::Python {
            version,
            gil: crate::GilMode::Conventional,
            debug: false,
        } if version.major == 3 && version.minor >= 11 => (RuntimeImplementation::Cpython, version),
        RuntimeAbi::Node {
            version,
            node_api,
            bridge_revision,
            ..
        } if *node_api > 0 && !bridge_revision.is_empty() => (RuntimeImplementation::Node, version),
        _ => return Err(invalid("unsupported runtime ABI capability")),
    };
    let numeric_version = format!(
        "{}.{}.{}",
        expected.1.major, expected.1.minor, expected.1.patch
    );
    let suffix = r.version.strip_prefix(&numeric_version);
    if r.implementation != expected.0
        || suffix.is_none_or(|s| !s.is_empty() && !s.starts_with(['a', 'b', 'r', '+', '-']))
    {
        return Err(invalid("runtime implementation/version differs from ABI"));
    }
    if ![
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ]
    .contains(&r.target.as_str())
    {
        return Err(invalid("unsupported compact target"));
    }
    if d.delivery == DeliveryMode::Memory && !d.payloads.is_empty() {
        return Err(invalid("memory delivery cannot have deployed payloads"));
    }
    if d.delivery == DeliveryMode::Compact {
        match r.provider {
            RuntimeProvider::Bundled => {
                validate_payload_path(&r.executable)?;
                let p = d
                    .payloads
                    .get(&r.executable)
                    .ok_or_else(|| invalid("bundled executable is undeclared"))?;
                if p.mode & 0o111 == 0 {
                    return Err(invalid("runtime executable has no execute permission"));
                }
            }
            RuntimeProvider::Host => {
                if !r.executable.starts_with('/') {
                    return Err(invalid("host runtime must be an explicit absolute path"));
                }
            }
        }
    }
    if d.launch.executable != r.executable {
        return Err(invalid("launch executable differs from selected runtime"));
    }
    if d.launch.args.iter().any(|a| a.contains('\0'))
        || d.launch
            .environment
            .iter()
            .any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
    {
        return Err(invalid("invalid launch argv/environment"));
    }
    for deployed in d.native.roots.values() {
        if !d.payloads.contains_key(deployed) {
            return Err(invalid("native root payload is undeclared"));
        }
    }
    for edge in &d.native.edges {
        if edge.name.is_empty() || !d.payloads.contains_key(&edge.from) {
            return Err(invalid("native edge has missing image/name"));
        }
        if matches!(
            edge.provider,
            DependencyProvider::Bundled | DependencyProvider::Runtime
        ) && !d.payloads.contains_key(&edge.resolved)
        {
            return Err(invalid("native dependency payload is undeclared"));
        }
    }
    Ok(())
}
