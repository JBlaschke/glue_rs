use crate::{FormatError, validate_digest, validate_resource_paths};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Provisional schema: bump before making an incompatible contract change.
pub const SCHEMA_VERSION: u32 = 0;
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub app_id: String,
    /// ID of a declared component, not a filesystem path.
    pub entrypoint: String,
    pub targets: BTreeMap<String, TargetProfile>,
    pub resources: BTreeMap<String, ResourceSpec>,
    pub runtimes: BTreeMap<String, RuntimeSpec>,
    pub components: BTreeMap<String, ComponentSpec>,
    pub native_modules: BTreeMap<String, NativeModuleSpec>,
    pub host_imports: BTreeMap<String, HostImportSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    /// Length of the uncompressed payload.
    pub size: u64,
    /// SHA-256 of the uncompressed payload, not its compressed representation.
    pub sha256: String,
    pub compression: Compression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    Stored,
    Deflate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub minimum_os_version: String,
    pub abi: TargetAbi,
    /// Explicit assumptions, checked by a future backend before mapping.
    pub page_sizes: BTreeSet<u32>,
    pub cpu_features: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
    Freebsd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetAbi {
    Glibc { minimum_version: String },
    Musl { minimum_version: String },
    Darwin,
    Msvc,
    Freebsd,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    pub target: String,
    /// Identity of the selected runtime build; it is not merely a library basename.
    pub build_id: String,
    pub abi: RuntimeAbi,
    pub provisioning: Provisioning,
    /// Requirements only. A declaration is not evidence that a backend supports them.
    pub required_features: BTreeSet<LoaderFeature>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "language", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeAbi {
    Python {
        version: RuntimeVersion,
        gil: GilMode,
        debug: bool,
    },
    Node {
        version: RuntimeVersion,
        node_api: u32,
        addon_abi: u32,
        bridge_revision: String,
    },
    Lua {
        version: RuntimeVersion,
        integer_bits: u8,
        number: LuaNumber,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GilMode {
    Conventional,
    FreeThreaded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LuaNumber {
    Float32,
    Float64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provisioning {
    Bundled {
        provider: BundledProvider,
        source: SourcePin,
        /// Canonical resource keys. The payload reader verifies their separate hashes.
        runtime_library: String,
        stdlib: String,
    },
    Host {
        runtime_library: String,
        stdlib: String,
        discovery: HostDiscovery,
    },
    /// A runtime bundled into the launcher at build time. Acquisition must match
    /// its compiled target/build/ABI/source descriptor; it is never a fallback
    /// for an explicitly selected archived or host runtime.
    Linked {
        provider: BundledProvider,
        source: SourcePin,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundledProvider {
    PythonBuildStandalone,
    CpythonSource,
    NodeSource,
    LuaSource,
    Custom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDiscovery {
    ExplicitPaths,
}

/// Build-time input pin. No provider may fetch this artifact at execution time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePin {
    pub release: String,
    pub revision: Option<String>,
    pub artifact: String,
    /// Digest of the original source/distribution artifact, before normalization.
    pub sha256: String,
    pub variant: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    pub runtime: String,
    /// Source/bytecode resource key. Language-specific interpretation comes later.
    pub entry_point: String,
    pub native_modules: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModuleSpec {
    pub target: String,
    pub resource: String,
    pub format: NativeFormat,
    pub namespace: String,
    pub runtime: Option<String>,
    pub dependencies: Vec<DependencySpec>,
    pub required_features: BTreeSet<LoaderFeature>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFormat {
    Elf,
    Pe,
    MachO,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencySpec {
    ArchivedModule { module: String },
    Runtime { runtime: String },
    OperatingSystem { import: String },
    HostModule { import: String },
}

/// Approved external dependencies, distinguished from bundled resources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostImportSpec {
    OperatingSystem {
        target: String,
        library: String,
        symbols: BTreeSet<String>,
    },
    HostModule {
        target: String,
        path: String,
        runtime: Option<String>,
        sha256: Option<String>,
    },
}

/// Binary capabilities to probe individually; none is advertised as implemented.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderFeature {
    FunctionExports,
    DataExports,
    Constructors,
    WeakSymbols,
    SymbolVersions,
    Tls,
    Unwind,
    Ifunc,
    DelayImports,
    PeStaticTls,
    MachOChainedFixups,
    ObjectiveC,
    Swift,
    AuthenticatedPointers,
    RuntimeAliases,
    NestedLoading,
}

impl Manifest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return invalid("manifest exceeds the byte limit");
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = StrictValue::deserialize(&mut deserializer)?.0;
        deserializer.end()?;
        let manifest: Self = serde_json::from_value(value)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Deterministic JSON: every object is emitted in lexicographic key order.
    pub fn to_json(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        let mut bytes = Vec::new();
        write_canonical_json(&value, &mut bytes)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return invalid("manifest exceeds the byte limit");
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FormatError::UnsupportedSchemaVersion(self.schema_version));
        }
        identifier(&self.app_id, "app ID")?;
        if self.targets.is_empty() {
            return invalid("at least one target is required");
        }
        if !self.components.contains_key(&self.entrypoint) {
            return invalid(format!(
                "entrypoint references missing component {:?}",
                self.entrypoint
            ));
        }
        validate_resource_paths(self.resources.keys())?;
        for resource in self.resources.values() {
            validate_digest(&resource.sha256)?;
        }
        for (id, target) in &self.targets {
            identifier(id, "target ID")?;
            numeric_version(&target.minimum_os_version, "minimum OS version")?;
            match (&target.os, &target.abi) {
                (
                    OperatingSystem::Linux,
                    TargetAbi::Glibc { minimum_version } | TargetAbi::Musl { minimum_version },
                ) => {
                    numeric_version(minimum_version, "minimum libc version")?;
                }
                (OperatingSystem::Macos, TargetAbi::Darwin)
                | (OperatingSystem::Windows, TargetAbi::Msvc)
                | (OperatingSystem::Freebsd, TargetAbi::Freebsd) => {}
                _ => return invalid(format!("target {id:?} has an ABI inconsistent with its OS")),
            }
            if target.page_sizes.is_empty()
                || target
                    .page_sizes
                    .iter()
                    .any(|size| !size.is_power_of_two() || *size < 4096 || *size > 65536)
            {
                return invalid(format!(
                    "target {id:?} needs explicit power-of-two page sizes between 4096 and 65536"
                ));
            }
            for feature in &target.cpu_features {
                identifier(feature, "CPU feature")?;
            }
        }
        for (id, runtime) in &self.runtimes {
            identifier(id, "runtime ID")?;
            nonempty(&runtime.build_id, "runtime build ID")?;
            let target = self.target(&runtime.target)?;
            runtime.abi.validate()?;
            validate_features(target.os, &runtime.required_features)?;
            match &runtime.provisioning {
                Provisioning::Bundled {
                    provider,
                    source,
                    runtime_library,
                    stdlib,
                } => {
                    source.validate()?;
                    self.resource(runtime_library)?;
                    self.resource(stdlib)?;
                    if runtime_library == stdlib {
                        return invalid("runtime library and stdlib must have distinct identities");
                    }
                    if !provider.matches(&runtime.abi) {
                        return invalid(format!(
                            "runtime {id:?} has a provider for a different language"
                        ));
                    }
                    if *provider == BundledProvider::PythonBuildStandalone
                        && target.os == OperatingSystem::Freebsd
                    {
                        return invalid(
                            "FreeBSD requires a separately pinned CPython source/custom producer, not PBS",
                        );
                    }
                    if *provider == BundledProvider::NodeSource && source.revision.is_none() {
                        return invalid(
                            "Node source and its bridge require explicit source revisions",
                        );
                    }
                }
                Provisioning::Host {
                    runtime_library,
                    stdlib,
                    discovery: HostDiscovery::ExplicitPaths,
                } => {
                    absolute_host_path(runtime_library, target.os)?;
                    absolute_host_path(stdlib, target.os)?;
                    if runtime_library == stdlib {
                        return invalid("host runtime library and stdlib must be distinct paths");
                    }
                }
                Provisioning::Linked { provider, source } => {
                    source.validate()?;
                    let RuntimeAbi::Lua { version, .. } = &runtime.abi else {
                        return invalid(
                            "the linked provider supports only official Lua 5.4 or 5.5",
                        );
                    };
                    if *provider != BundledProvider::LuaSource {
                        return invalid("the initial linked Lua provider requires lua_source");
                    }
                    // RuntimeAbi::validate already enforces the fixed numeric
                    // configuration. Unlike PBS release dates, a linked Lua
                    // source release must identify this exact ABI patch version.
                    let expected_release =
                        format!("{}.{}.{}", version.major, version.minor, version.patch);
                    if source.release != expected_release {
                        return invalid(format!(
                            "linked Lua source release {:?} differs from exact ABI release {expected_release:?}",
                            source.release
                        ));
                    }
                }
            }
        }
        for (id, component) in &self.components {
            identifier(id, "component ID")?;
            let runtime = self.runtime(&component.runtime)?;
            self.resource(&component.entry_point)?;
            for module_id in &component.native_modules {
                let module = self.native_modules.get(module_id).ok_or_else(|| {
                    error(format!(
                        "component {id:?} references missing native module {module_id:?}"
                    ))
                })?;
                same_target(&runtime.target, &module.target, "component native module")?;
                if let Some(module_runtime) = &module.runtime {
                    if module_runtime != &component.runtime {
                        return invalid(format!(
                            "component {id:?} uses a module bound to another runtime"
                        ));
                    }
                }
            }
        }
        for (id, import) in &self.host_imports {
            identifier(id, "host import ID")?;
            match import {
                HostImportSpec::OperatingSystem {
                    target,
                    library,
                    symbols,
                } => {
                    self.target(target)?;
                    nonempty(library, "OS library identity")?;
                    for symbol in symbols {
                        nonempty(symbol, "OS symbol")?;
                    }
                }
                HostImportSpec::HostModule {
                    target,
                    path,
                    runtime,
                    sha256,
                } => {
                    absolute_host_path(path, self.target(target)?.os)?;
                    if let Some(runtime) = runtime {
                        same_target(
                            target,
                            &self.runtime(runtime)?.target,
                            "host module runtime",
                        )?;
                    }
                    if let Some(sha256) = sha256 {
                        validate_digest(sha256)?;
                    }
                }
            }
        }
        for (id, module) in &self.native_modules {
            identifier(id, "native module ID")?;
            identifier(&module.namespace, "native namespace")?;
            let target = self.target(&module.target)?;
            self.resource(&module.resource)?;
            let expected = match target.os {
                OperatingSystem::Linux | OperatingSystem::Freebsd => NativeFormat::Elf,
                OperatingSystem::Macos => NativeFormat::MachO,
                OperatingSystem::Windows => NativeFormat::Pe,
            };
            if module.format != expected {
                return invalid(format!(
                    "module {id:?} binary format disagrees with its target"
                ));
            }
            validate_features(target.os, &module.required_features)?;
            if let Some(runtime) = &module.runtime {
                same_target(
                    &module.target,
                    &self.runtime(runtime)?.target,
                    "native module runtime",
                )?;
            }
            let mut seen = BTreeSet::new();
            for dependency in &module.dependencies {
                let key = match dependency {
                    DependencySpec::ArchivedModule { module: dependency } => {
                        let dependency_spec =
                            self.native_modules.get(dependency).ok_or_else(|| {
                                error(format!(
                                    "module {id:?} references missing dependency {dependency:?}"
                                ))
                            })?;
                        same_target(
                            &module.target,
                            &dependency_spec.target,
                            "archived dependency",
                        )?;
                        if let Some(bound) = &dependency_spec.runtime {
                            if module.runtime.as_ref() != Some(bound) {
                                return invalid(
                                    "a runtime-bound archived dependency requires the same explicit module runtime identity",
                                );
                            }
                        }
                        (0, dependency)
                    }
                    DependencySpec::Runtime { runtime } => {
                        same_target(
                            &module.target,
                            &self.runtime(runtime)?.target,
                            "runtime dependency",
                        )?;
                        if module.runtime.as_ref() != Some(runtime) {
                            return invalid(
                                "a runtime dependency requires the same explicit module runtime identity",
                            );
                        }
                        (1, runtime)
                    }
                    DependencySpec::OperatingSystem { import } => {
                        match self.host_imports.get(import) {
                            Some(HostImportSpec::OperatingSystem { target, .. }) => {
                                same_target(&module.target, target, "OS dependency")?
                            }
                            _ => {
                                return invalid(format!(
                                    "module {id:?} references missing or misclassified OS import {import:?}"
                                ));
                            }
                        }
                        (2, import)
                    }
                    DependencySpec::HostModule { import } => {
                        match self.host_imports.get(import) {
                            Some(HostImportSpec::HostModule {
                                target, runtime, ..
                            }) => {
                                same_target(&module.target, target, "host dependency")?;
                                if let Some(bound) = runtime {
                                    if module.runtime.as_ref() != Some(bound) {
                                        return invalid(
                                            "a runtime-bound host dependency requires the same explicit module runtime identity",
                                        );
                                    }
                                }
                            }
                            _ => {
                                return invalid(format!(
                                    "module {id:?} references missing or misclassified host module {import:?}"
                                ));
                            }
                        }
                        (3, import)
                    }
                };
                if !seen.insert(key) {
                    return invalid(format!("module {id:?} has a duplicate dependency edge"));
                }
            }
        }
        Ok(())
    }

    fn target(&self, id: &str) -> Result<&TargetProfile, FormatError> {
        self.targets
            .get(id)
            .ok_or_else(|| error(format!("missing target {id:?}")))
    }
    fn runtime(&self, id: &str) -> Result<&RuntimeSpec, FormatError> {
        self.runtimes
            .get(id)
            .ok_or_else(|| error(format!("missing runtime {id:?}")))
    }
    fn resource(&self, path: &str) -> Result<(), FormatError> {
        if self.resources.contains_key(path) {
            Ok(())
        } else {
            invalid(format!("missing resource {path:?}"))
        }
    }
}

impl RuntimeAbi {
    fn validate(&self) -> Result<(), FormatError> {
        match self {
            Self::Python {
                version,
                gil,
                debug,
            } => {
                if version.major != 3 {
                    return invalid("initial Python contract requires CPython 3");
                }
                if *gil != GilMode::Conventional || *debug {
                    return invalid(
                        "initial Python profile requires a conventional GIL and non-debug ABI",
                    );
                }
            }
            Self::Node {
                version,
                node_api,
                addon_abi,
                bridge_revision,
            } => {
                if version.major == 0 || *node_api == 0 || *addon_abi == 0 {
                    return invalid("Node version and ABI identities must be nonzero");
                }
                nonempty(bridge_revision, "Node bridge revision")?;
            }
            Self::Lua {
                version,
                integer_bits,
                number,
            } => {
                if version.major != 5
                    || !matches!(version.minor, 4 | 5)
                    || *integer_bits != 64
                    || *number != LuaNumber::Float64
                {
                    return invalid(
                        "Lua contract requires official Lua 5.4 or 5.5 with 64-bit integers and float64 numbers",
                    );
                }
            }
        }
        Ok(())
    }
}

impl SourcePin {
    fn validate(&self) -> Result<(), FormatError> {
        nonempty(&self.release, "source release")?;
        nonempty(&self.artifact, "source artifact")?;
        nonempty(&self.variant, "source variant")?;
        if self.release.contains(['*', '^', '~', '<', '>'])
            || matches!(
                self.release.as_str(),
                "latest" | "stable" | "main" | "master"
            )
        {
            return invalid(
                "source release must be exact, not a moving alias or version constraint",
            );
        }
        if let Some(revision) = &self.revision {
            nonempty(revision, "source revision")?;
            if matches!(revision.as_str(), "latest" | "stable" | "main" | "master") {
                return invalid("source revision must not be a moving branch alias");
            }
        }
        validate_digest(&self.sha256)
    }
}

impl BundledProvider {
    fn matches(self, abi: &RuntimeAbi) -> bool {
        matches!(
            (self, abi),
            (
                Self::PythonBuildStandalone | Self::CpythonSource,
                RuntimeAbi::Python { .. }
            ) | (Self::NodeSource, RuntimeAbi::Node { .. })
                | (Self::LuaSource, RuntimeAbi::Lua { .. })
                | (Self::Custom, _)
        )
    }
}

fn validate_features(
    os: OperatingSystem,
    features: &BTreeSet<LoaderFeature>,
) -> Result<(), FormatError> {
    for feature in features {
        let applicable = match feature {
            LoaderFeature::SymbolVersions | LoaderFeature::Ifunc => {
                matches!(os, OperatingSystem::Linux | OperatingSystem::Freebsd)
            }
            LoaderFeature::DelayImports | LoaderFeature::PeStaticTls => {
                os == OperatingSystem::Windows
            }
            LoaderFeature::MachOChainedFixups
            | LoaderFeature::ObjectiveC
            | LoaderFeature::Swift
            | LoaderFeature::AuthenticatedPointers => os == OperatingSystem::Macos,
            _ => true,
        };
        if !applicable {
            return invalid(format!(
                "loader feature {feature:?} does not apply to {os:?}"
            ));
        }
    }
    Ok(())
}

fn identifier(value: &str, field: &str) -> Result<(), FormatError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return invalid(format!(
            "{field} must use 1..255 ASCII letters, digits, dots, underscores or hyphens"
        ));
    }
    Ok(())
}

fn nonempty(value: &str, field: &str) -> Result<(), FormatError> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return invalid(format!(
            "{field} must be nonempty, bounded and free of control characters"
        ));
    }
    Ok(())
}

fn numeric_version(value: &str, field: &str) -> Result<(), FormatError> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.is_empty()
        || parts.len() > 4
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || part.parse::<u32>().is_err()
        })
    {
        return invalid(format!(
            "{field} must contain one to four numeric version components"
        ));
    }
    Ok(())
}

fn absolute_host_path(path: &str, os: OperatingSystem) -> Result<(), FormatError> {
    nonempty(path, "host path")?;
    let bytes = path.as_bytes();
    let absolute = match os {
        OperatingSystem::Windows => {
            (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'/' | b'\\'))
                || path.starts_with("\\\\")
                || path.starts_with("//")
        }
        _ => path.starts_with('/'),
    };
    if !absolute {
        return invalid(format!(
            "host path {path:?} must be absolute for {os:?}; environment/PATH discovery is disabled"
        ));
    }
    if path
        .split(['/', '\\'])
        .any(|component| component == "." || component == "..")
    {
        return invalid(format!(
            "host path {path:?} must not contain traversal components"
        ));
    }
    Ok(())
}

fn same_target(left: &str, right: &str, context: &str) -> Result<(), FormatError> {
    if left == right {
        Ok(())
    } else {
        invalid(format!(
            "{context} crosses target slices {left:?} and {right:?}"
        ))
    }
}
fn error(message: impl Into<String>) -> FormatError {
    FormatError::InvalidManifest(message.into())
}
fn invalid<T>(message: impl Into<String>) -> Result<T, FormatError> {
    Err(error(message))
}

// serde_json::Value normally keeps only the last duplicate key. Decode through
// this visitor first so duplicates at every depth fail before typed deserialization.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| StrictValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
                    }
                    values.insert(key, access.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn write_canonical_json(value: &Value, bytes: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        Value::Object(map) => {
            bytes.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                serde_json::to_writer(&mut *bytes, key)?;
                bytes.push(b':');
                write_canonical_json(value, bytes)?;
            }
            bytes.push(b'}');
        }
        Value::Array(values) => {
            bytes.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write_canonical_json(value, bytes)?;
            }
            bytes.push(b']');
        }
        _ => serde_json::to_writer(bytes, value)?,
    }
    Ok(())
}
