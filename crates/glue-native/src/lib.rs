//! Experimental, single-closure GNU Linux native Lua loader (ADR 0008).
//!
//! Inspection and closure validation are portable and execute no payload.
//! Loading is deliberately private, dependency-first and process-pinned. Native
//! code is trusted C code obeying the selected Lua ABI, not a sandboxed resource.

pub mod elf;

#[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64"))]
#[allow(unsafe_code)]
mod linux;

use elf::{ElfFacts, SymbolBinding, SymbolKind};
use glue_format::{
    Architecture, BundledProvider, DependencySpec, HostImportSpec, LoaderFeature, LuaNumber,
    Manifest, NativeFormat, OperatingSystem, Provisioning, RuntimeAbi, TargetAbi,
};
use glue_resources::Resources;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
    sync::Arc,
};

const MAX_IMAGES: usize = 16;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLOSURE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("invalid native Lua closure: {0}")]
    Invalid(String),
    #[error("native Lua closure is unsupported: {0}")]
    Unsupported(String),
    #[error("native Lua loader failed: {0}")]
    Load(String),
}

/// An already resolved C initializer. Only this crate can construct one.
/// Its image and dependency handles remain pinned through Lua close and until
/// process exit, including failed initialization. Rust never invokes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeInitializer {
    address: u64,
}

impl NativeInitializer {
    /// Private C reply protocol address representation, not an invocation API.
    pub fn address(&self) -> u64 {
        self.address
    }
}

#[derive(Debug)]
#[cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")),
    allow(dead_code)
)]
struct Root {
    resource: String,
    symbol: String,
    module: String,
}

/// Cached, process-pinned initializer leases. No loader activity occurs in these
/// lookup methods, which may be called beneath the C archive trampoline.
#[derive(Debug)]
pub struct NativeManager {
    roots: BTreeMap<String, (Root, NativeInitializer)>,
}

impl NativeManager {
    pub fn by_name(&self, name: &str) -> Option<(&str, NativeInitializer)> {
        self.roots
            .get(name)
            .map(|(root, function)| (root.resource.as_str(), function.clone()))
    }

    pub fn by_resource(&self, resource: &str) -> Option<(&str, NativeInitializer)> {
        self.roots.values().find_map(|(root, function)| {
            (root.resource == resource).then(|| (root.symbol.as_str(), function.clone()))
        })
    }
}

#[derive(Debug)]
#[cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")),
    allow(dead_code)
)]
enum Provider {
    Archived { module: String, symbol: usize },
    Runtime(String),
    OperatingSystem { symbol: String, version: String },
    WeakNull,
}

#[derive(Debug)]
#[cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")),
    allow(dead_code)
)]
struct Image {
    bytes: Arc<[u8]>,
    facts: ElfFacts,
    providers: BTreeMap<usize, Provider>,
}

/// Verified images and a completely resolved dependency graph. Preparing this
/// value checks all hashes and formats before the loader can run constructors.
#[derive(Debug)]
#[cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")),
    allow(dead_code)
)]
pub struct NativePlan {
    images: BTreeMap<String, Image>,
    order: Vec<String>,
    roots: BTreeMap<String, Root>,
    runtime_exports: BTreeSet<String>,
}

/// Validate schema conventions and capability claims without reading an image.
pub fn validate_manifest(manifest: &Manifest) -> Result<(), NativeError> {
    manifest.validate().map_err(|e| invalid(e.to_string()))?;
    let component = &manifest.components[&manifest.entrypoint];
    let runtime = &manifest.runtimes[&component.runtime];
    let target = &manifest.targets[&runtime.target];
    if manifest.components.len() != 1 || manifest.runtimes.len() != 1 || manifest.targets.len() != 1
    {
        return Err(unsupported(
            "requires exactly one component, runtime and target",
        ));
    }
    let RuntimeAbi::Lua {
        version: lua_version,
        integer_bits: 64,
        number: LuaNumber::Float64,
    } = &runtime.abi
    else {
        return Err(unsupported("requires linked Lua with int64/float64 ABI"));
    };
    if lua_version.major != 5 || !matches!((lua_version.minor, lua_version.patch), (4, 9) | (5, 1))
    {
        return Err(unsupported("requires Lua 5.4.9 or 5.5.1"));
    }
    if !matches!(
        runtime.provisioning,
        Provisioning::Linked {
            provider: BundledProvider::LuaSource,
            ..
        }
    ) {
        return Err(unsupported("requires the linked lua_source provider"));
    }
    if target.os != OperatingSystem::Linux
        || target.arch != Architecture::Aarch64
        || !matches!(target.abi, TargetAbi::Glibc { .. })
        || target.page_sizes != BTreeSet::from([4096])
    {
        return Err(unsupported(
            "requires GNU Linux AArch64 with exactly 4096-byte pages",
        ));
    }
    if version(&target.minimum_os_version)? < [6, 3, 0] {
        return Err(invalid(
            "explicit MFD_EXEC requires a declared Linux floor of at least 6.3",
        ));
    }
    check_features(&runtime.required_features)?;
    if manifest.native_modules.len() > MAX_IMAGES {
        return Err(unsupported("at most 16 native images are supported"));
    }
    let mut sonames = BTreeSet::new();
    let mut resources = BTreeSet::new();
    let mut used_imports = BTreeSet::new();
    for (id, module) in &manifest.native_modules {
        if module.target != runtime.target || module.format != NativeFormat::Elf {
            return Err(invalid(format!(
                "module {id:?} must use the selected ELF target"
            )));
        }
        if module.namespace != "linked-lua" {
            return Err(unsupported("only namespace linked-lua is supported"));
        }
        check_features(&module.required_features)?;
        let soname = basename(&module.resource)?;
        if !sonames.insert(soname) || !resources.insert(&module.resource) {
            return Err(invalid("duplicate native SONAME or resource"));
        }
        let mut edges = BTreeSet::new();
        let mut runtime_edges = 0;
        for dependency in &module.dependencies {
            let edge = match dependency {
                DependencySpec::ArchivedModule { module: dependency } => {
                    if dependency == id {
                        return Err(invalid("self dependency"));
                    }
                    format!("module:{dependency}")
                }
                DependencySpec::Runtime {
                    runtime: dependency,
                } => {
                    if dependency != &component.runtime
                        || module.runtime.as_ref() != Some(dependency)
                    {
                        return Err(invalid("runtime edge must identify the linked Lua runtime"));
                    }
                    runtime_edges += 1;
                    format!("runtime:{dependency}")
                }
                DependencySpec::OperatingSystem { import } => {
                    used_imports.insert(import);
                    format!("os:{import}")
                }
                DependencySpec::HostModule { .. } => {
                    return Err(unsupported("host native modules are pending"));
                }
            };
            if !edges.insert(edge) {
                return Err(invalid("duplicate dependency edge"));
            }
        }
        if module
            .runtime
            .as_ref()
            .is_some_and(|id| id != &component.runtime)
            || runtime_edges != usize::from(module.runtime.is_some())
        {
            return Err(invalid(
                "module runtime binding requires one exact runtime edge",
            ));
        }
    }
    for (id, import) in &manifest.host_imports {
        let HostImportSpec::OperatingSystem {
            target,
            library,
            symbols,
        } = import
        else {
            return Err(unsupported("host imports are pending"));
        };
        if target != &runtime.target || library != "libc.so.6" {
            return Err(unsupported(
                "only the selected target's libc.so.6 is supported",
            ));
        }
        // Expand this allowlist only with individual ABI and binding evidence.
        if symbols.is_empty() || symbols.iter().any(|symbol| symbol != "getpid") {
            return Err(unsupported(
                "the reviewed libc import allowlist contains only getpid",
            ));
        }
        if !used_imports.contains(id) {
            return Err(invalid("unused OS import declaration"));
        }
    }
    for id in &component.native_modules {
        let module = &manifest.native_modules[id];
        initializer_name(id)?;
        if module.runtime.as_ref() != Some(&component.runtime) {
            return Err(invalid("Lua native roots require an exact runtime binding"));
        }
    }
    let order = dependency_order(manifest)?;
    if order.len() != manifest.native_modules.len() {
        return Err(invalid(
            "native images outside the selected component closure",
        ));
    }
    Ok(())
}

impl NativePlan {
    /// The runtime adapter must first validate its compiled core's exact
    /// source/build identity; this manager validates Lua ABI declarations,
    /// closure ownership and the adapter's reviewed export policy.
    pub fn prepare<R: Read + Seek>(
        resources: &mut Resources<R>,
        runtime_exports: &BTreeSet<String>,
    ) -> Result<Self, NativeError> {
        validate_manifest(resources.manifest())?;
        if runtime_exports.iter().any(|name| {
            matches!(
                name.as_str(),
                "lua_newstate" | "luaL_newstate" | "lua_close"
            ) || !(name.starts_with("lua_") || name.starts_with("luaL_"))
        }) {
            return Err(invalid(
                "runtime export policy cannot admit state creation, destruction or non-Lua symbols",
            ));
        }
        let manifest = resources.manifest().clone();
        let component = &manifest.components[&manifest.entrypoint];
        let runtime = &manifest.runtimes[&component.runtime];
        let TargetAbi::Glibc { minimum_version } = &manifest.targets[&runtime.target].abi else {
            unreachable!("validated GNU target")
        };
        let floor = version(minimum_version)?;
        let order = dependency_order(&manifest)?;
        let mut payloads = BTreeMap::new();
        let mut total = 0usize;
        // Read every image before inspection/loading. Resources verifies all
        // compressed lengths, CRCs and SHA-256 digests before publishing bytes.
        for id in &order {
            let resource = &manifest.native_modules[id].resource;
            if resources
                .stat(resource)
                .map_err(|e| invalid(e.to_string()))?
                .size
                > MAX_IMAGE_BYTES as u64
            {
                return Err(unsupported("native image exceeds 16 MiB"));
            }
            let bytes = resources
                .read(resource)
                .map_err(|e| invalid(e.to_string()))?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("closure size overflow"))?;
            if total > MAX_CLOSURE_BYTES {
                return Err(unsupported("native closure exceeds 64 MiB"));
            }
            payloads.insert(id.clone(), bytes);
        }
        let mut images: BTreeMap<String, Image> = BTreeMap::new();
        let mut definitions: BTreeMap<String, String> = BTreeMap::new();
        for id in &order {
            let module = &manifest.native_modules[id];
            let mut allowed = BTreeSet::new();
            let mut candidates = BTreeMap::new();
            let mut needed = BTreeSet::new();
            for dependency in &module.dependencies {
                match dependency {
                    DependencySpec::ArchivedModule { module: dependency } => {
                        let image = &images[dependency];
                        needed.insert(image.facts.soname.clone());
                        for symbol in &image.facts.symbols {
                            if exported(symbol) {
                                allowed.insert(symbol.name.clone());
                                candidates.insert(
                                    symbol.name.clone(),
                                    Provider::Archived {
                                        module: dependency.clone(),
                                        symbol: symbol.index,
                                    },
                                );
                            }
                        }
                    }
                    DependencySpec::Runtime { .. } => {
                        for symbol in runtime_exports {
                            allowed.insert(symbol.clone());
                            candidates.insert(symbol.clone(), Provider::Runtime(symbol.clone()));
                        }
                    }
                    DependencySpec::OperatingSystem { import } => {
                        let HostImportSpec::OperatingSystem {
                            library, symbols, ..
                        } = &manifest.host_imports[import]
                        else {
                            unreachable!("validated OS import")
                        };
                        needed.insert(library.clone());
                        allowed.extend(symbols.iter().cloned());
                    }
                    DependencySpec::HostModule { .. } => unreachable!("validated dependency"),
                }
            }
            let bytes = payloads.remove(id).expect("verified image");
            let facts =
                elf::inspect(&bytes, basename(&module.resource)?, &allowed).map_err(|error| {
                    match error {
                        elf::ElfError::Invalid(message) => invalid(format!("{id}: {message}")),
                        elf::ElfError::Unsupported(message) => {
                            unsupported(format!("{id}: {message}"))
                        }
                    }
                })?;
            if facts.needed.iter().cloned().collect::<BTreeSet<_>>() != needed {
                return Err(invalid(format!(
                    "{id}: ELF NEEDED differs from declared direct dependencies"
                )));
            }
            let features = &module.required_features;
            if facts.has_constructors && !features.contains(&LoaderFeature::Constructors) {
                return Err(invalid(format!("{id}: constructors are not declared")));
            }
            if !facts.version_requirements.is_empty()
                && !features.contains(&LoaderFeature::SymbolVersions)
            {
                return Err(invalid(format!("{id}: symbol versions are not declared")));
            }
            for requirement in &facts.version_requirements {
                if requirement.library != "libc.so.6"
                    || requirement.flags != 0
                    || !requirement.name.starts_with("GLIBC_")
                    || version(&requirement.name[6..])? > floor
                {
                    return Err(invalid(format!(
                        "{id}: unsupported libc symbol version or declared floor"
                    )));
                }
            }
            let own_initializer = component
                .native_modules
                .contains(id)
                .then(|| initializer_name(id))
                .transpose()?;
            let mut providers = BTreeMap::new();
            for symbol in &facts.symbols {
                if symbol.binding == SymbolBinding::Weak
                    && !features.contains(&LoaderFeature::WeakSymbols)
                {
                    return Err(invalid(format!("{id}: weak symbols are not declared")));
                }
                if symbol.defined
                    && (symbol.name.starts_with("lua_")
                        || symbol.name.starts_with("luaL_")
                        || symbol.name.starts_with("luaopen_"))
                    && own_initializer.as_ref() != Some(&symbol.name)
                {
                    return Err(invalid(format!(
                        "{id}: payload defines Lua runtime symbol {}",
                        symbol.name
                    )));
                }
                if exported(symbol) {
                    if let Some(previous) = definitions.insert(symbol.name.clone(), id.clone()) {
                        return Err(invalid(format!(
                            "duplicate export {} in {previous} and {id}",
                            symbol.name
                        )));
                    }
                    let feature = match symbol.kind {
                        SymbolKind::Function => LoaderFeature::FunctionExports,
                        SymbolKind::Object => LoaderFeature::DataExports,
                        _ => {
                            return Err(unsupported(
                                "only function and data exports are supported",
                            ));
                        }
                    };
                    if !features.contains(&feature) {
                        return Err(invalid(format!("{id}: export feature is not declared")));
                    }
                }
                if symbol.defined || symbol.name.is_empty() {
                    continue;
                }
                let provider = if let Some(provider) = candidates.remove(&symbol.name) {
                    if symbol.version_index > 1 {
                        return Err(unsupported(
                            "versioned archived or runtime imports are pending",
                        ));
                    }
                    if matches!(provider, Provider::Runtime(_))
                        && !features.contains(&LoaderFeature::RuntimeAliases)
                    {
                        return Err(invalid(format!(
                            "{id}: linked runtime aliases are not declared"
                        )));
                    }
                    provider
                } else if allowed.contains(&symbol.name) {
                    let requirement = facts
                        .version_requirements
                        .iter()
                        .find(|entry| entry.index == symbol.version_index)
                        .ok_or_else(|| invalid("OS symbol must name an explicit GLIBC version"))?;
                    Provider::OperatingSystem {
                        symbol: symbol.name.clone(),
                        version: requirement.name.clone(),
                    }
                } else if symbol.binding == SymbolBinding::Weak {
                    if !features.contains(&LoaderFeature::WeakSymbols) {
                        return Err(invalid("weak imports are not declared"));
                    }
                    Provider::WeakNull
                } else {
                    return Err(invalid(format!("{id}: undeclared import {}", symbol.name)));
                };
                providers.insert(symbol.index, provider);
            }
            if let Some(initializer) = &own_initializer {
                let symbol = facts
                    .symbol(initializer)
                    .ok_or_else(|| invalid("missing root initializer"))?;
                if !exported(symbol)
                    || symbol.kind != SymbolKind::Function
                    || !facts.contains_executable_address(symbol.value)
                {
                    return Err(invalid("initializer must be a defined, visible function"));
                }
            }
            images.insert(
                id.clone(),
                Image {
                    bytes,
                    facts,
                    providers,
                },
            );
        }
        let roots = component
            .native_modules
            .iter()
            .map(|id| {
                Ok((
                    id.clone(),
                    Root {
                        module: id.clone(),
                        resource: manifest.native_modules[id].resource.clone(),
                        symbol: initializer_name(id)?,
                    },
                ))
            })
            .collect::<Result<_, NativeError>>()?;
        Ok(Self {
            images,
            order,
            roots,
            runtime_exports: runtime_exports.clone(),
        })
    }

    /// Load the prepared closure before creating any Lua state.
    pub fn load(self) -> Result<NativeManager, NativeError> {
        if self.images.is_empty() {
            return Ok(NativeManager {
                roots: BTreeMap::new(),
            });
        }
        #[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64"))]
        {
            linux::load(self)
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")))]
        {
            Err(unsupported("native loading requires GNU Linux AArch64"))
        }
    }
}

fn exported(symbol: &elf::DynamicSymbol) -> bool {
    symbol.defined
        && !symbol.name.is_empty()
        && matches!(symbol.binding, SymbolBinding::Global | SymbolBinding::Weak)
        && symbol.visibility == 0
}

fn basename(resource: &str) -> Result<&str, NativeError> {
    let name = resource.rsplit('/').next().unwrap_or("");
    if !name.starts_with("lib")
        || !name.ends_with(".so")
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name == "libc.so"
        || name.starts_with("liblua")
    {
        return Err(invalid(
            "native resource basename must be a private lib*.so SONAME",
        ));
    }
    Ok(name)
}

fn initializer_name(name: &str) -> Result<String, NativeError> {
    if name.len() > 128
        || name.split('.').any(|part| {
            part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        return Err(invalid(
            "native import names require ASCII dotted identifiers without hyphens",
        ));
    }
    Ok(format!("luaopen_{}", name.replace('.', "_")))
}

fn check_features(features: &BTreeSet<LoaderFeature>) -> Result<(), NativeError> {
    for feature in features {
        if !matches!(
            feature,
            LoaderFeature::FunctionExports
                | LoaderFeature::DataExports
                | LoaderFeature::Constructors
                | LoaderFeature::WeakSymbols
                | LoaderFeature::SymbolVersions
                | LoaderFeature::RuntimeAliases
        ) {
            return Err(unsupported(format!(
                "unobserved loader feature {feature:?}"
            )));
        }
    }
    Ok(())
}

fn dependency_order(manifest: &Manifest) -> Result<Vec<String>, NativeError> {
    fn visit(
        id: &str,
        manifest: &Manifest,
        visiting: &mut BTreeSet<String>,
        seen: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) -> Result<(), NativeError> {
        if seen.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(invalid("dependency cycle"));
        }
        for dependency in &manifest.native_modules[id].dependencies {
            if let DependencySpec::ArchivedModule { module } = dependency {
                visit(module, manifest, visiting, seen, order)?;
            }
        }
        visiting.remove(id);
        seen.insert(id.to_owned());
        order.push(id.to_owned());
        Ok(())
    }
    let mut order = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for id in &manifest.components[&manifest.entrypoint].native_modules {
        visit(id, manifest, &mut visiting, &mut seen, &mut order)?;
    }
    Ok(order)
}

fn version(value: &str) -> Result<[u32; 3], NativeError> {
    let mut result = [0; 3];
    for (index, part) in value.split('.').enumerate() {
        if index >= result.len() || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid numeric version"));
        }
        result[index] = part
            .parse()
            .map_err(|_| invalid("numeric version overflow"))?;
    }
    Ok(result)
}

fn invalid(message: impl Into<String>) -> NativeError {
    NativeError::Invalid(message.into())
}
fn unsupported(message: impl Into<String>) -> NativeError {
    NativeError::Unsupported(message.into())
}

#[cfg(test)]
mod closure_tests;
