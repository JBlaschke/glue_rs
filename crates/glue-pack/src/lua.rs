//! Consume a Lua project and an optional already-installed LuaRocks tree.
//! Discovery reads existing files only; it never invokes a package manager or compiler.

use crate::distribution::{self, DistributionInput, DistributionLimits, PayloadSource};
use glue_format::{
    Diagnostic, DiagnosticCode, InputIdentity, LuaNumber, NativeInventory, ResourcePath,
    RuntimeAbi, RuntimeDescriptor, RuntimeImplementation, RuntimeLaunchSpec, RuntimeProvider,
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct LuaProjectOptions {
    pub project: PathBuf,
    /// Project-relative entry; configuration defaults should be resolved by the CLI.
    pub entry: Option<String>,
    pub rocks_tree: Option<PathBuf>,
    pub output: Option<PathBuf>,
    /// Exact descriptor obtained by probing the selected linked helper.
    pub runtime: RuntimeDescriptor,
    pub helper_executable: PathBuf,
    /// Exact paths or directory prefixes ending in `/**`.
    pub exclusions: Vec<String>,
    /// Logical native root path -> explicitly declared Lua family.
    pub native_abis: BTreeMap<String, String>,
    pub native_search: Vec<PathBuf>,
    pub normalize_native_paths: bool,
}

fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "check the Lua project, entry and selected helper",
    )
}

fn read(path: &Path, remaining: u64) -> Result<Vec<u8>, Diagnostic> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(remaining.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|e| {
            error(
                DiagnosticCode::MissingInput,
                format!("{}: {e}", path.display()),
            )
        })?;
    if bytes.len() as u64 > remaining {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "Lua inputs exceed configured byte bound",
        ));
    }
    Ok(bytes)
}

fn native(path: &str) -> bool {
    path.ends_with(".so")
        || path.contains(".so.")
        || path.ends_with(".dylib")
        || path.ends_with(".dll")
}

fn excluded(path: &str, exclusions: &[String]) -> bool {
    exclusions.iter().any(|pattern| {
        if let Some(directory) = pattern.strip_suffix("/**") {
            path == directory
                || path
                    .strip_prefix(directory)
                    .is_some_and(|tail| tail.starts_with('/'))
        } else {
            path == pattern
        }
    })
}

fn insert(
    logical: String,
    source: PathBuf,
    input: &mut DistributionInput,
    total: &mut u64,
    limits: DistributionLimits,
) -> Result<(), Diagnostic> {
    ResourcePath::new(&logical).map_err(|e| error(DiagnosticCode::PathEscape, e.to_string()))?;
    if input.resources.contains_key(&logical) || input.native.roots.contains_key(&logical) {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            format!("duplicate Lua module/resource {logical:?}"),
        ));
    }
    if native(&logical) {
        let deployed = format!(
            "native/lua/{}",
            logical.strip_prefix("app/").unwrap_or(&logical)
        );
        input.native.roots.insert(logical, deployed.clone());
        input.payloads.insert(deployed, PayloadSource::File(source));
    } else {
        let bytes = read(&source, limits.max_input_bytes.saturating_sub(*total))?;
        *total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
            error(
                DiagnosticCode::ResourceLimit,
                "Lua input byte count overflow",
            )
        })?;
        input.resources.insert(logical, bytes);
    }
    Ok(())
}

/// Construct the shared distribution input, preserving logical module paths.
pub fn ingest(
    options: &LuaProjectOptions,
    limits: DistributionLimits,
) -> Result<DistributionInput, Diagnostic> {
    let RuntimeAbi::Lua {
        version,
        integer_bits: 64,
        number: LuaNumber::Float64,
    } = options.runtime.abi
    else {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            "Lua requires an int64/float64 helper descriptor",
        ));
    };
    if options.runtime.implementation != RuntimeImplementation::Lua
        || options.runtime.provider != RuntimeProvider::Bundled
        || version.major != 5
        || ![4, 5].contains(&version.minor)
    {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            "select an official bundled Lua 5.4 or 5.5 helper",
        ));
    }
    let family = format!("5.{}", version.minor);
    for pattern in &options.exclusions {
        let path = pattern.strip_suffix("/**").unwrap_or(pattern);
        ResourcePath::new(path)
            .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    }
    let project = fs::canonicalize(&options.project).map_err(|e| {
        error(
            DiagnosticCode::MissingInput,
            format!("{}: {e}", options.project.display()),
        )
    })?;
    let max_files = usize::try_from(limits.archive.max_entries).unwrap_or(usize::MAX);
    let files = distribution::collect_tree(&project, options.output.as_deref(), max_files)?;
    let entry = if let Some(entry) = &options.entry {
        ResourcePath::new(entry).map_err(|e| error(DiagnosticCode::PathEscape, e.to_string()))?;
        entry.clone()
    } else if files.contains_key("main.lua") {
        "main.lua".to_owned()
    } else {
        let candidates: Vec<_> = files
            .keys()
            .filter(|path| path.ends_with(".lua"))
            .take(4)
            .cloned()
            .collect();
        return Err(error(
            DiagnosticCode::MissingEntry,
            format!("main.lua is absent; select --entry explicitly (candidates: {candidates:?})"),
        ));
    };
    if !entry.ends_with(".lua")
        || !files.contains_key(&entry)
        || excluded(&entry, &options.exclusions)
    {
        return Err(error(
            DiagnosticCode::MissingEntry,
            format!("Lua entry {entry:?} is missing, excluded or not source text"),
        ));
    }
    let helper_bytes = read(&options.helper_executable, limits.max_payload_bytes)?;
    let helper_identity = InputIdentity::of(&helper_bytes);
    if !options
        .runtime
        .inputs
        .values()
        .any(|identity| identity == &helper_identity)
    {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            "selected helper bytes differ from the probed runtime identity",
        ));
    }
    let mut input = DistributionInput {
        app_id: "lua.application".to_owned(),
        entrypoint: format!("app/{entry}"),
        runtime: options.runtime.clone(),
        launch: RuntimeLaunchSpec {
            executable: options.runtime.executable.clone(),
            args: vec!["run".to_owned(), "{archive}".to_owned(), "--".to_owned()],
            environment: BTreeMap::new(),
            clear_environment: false,
        },
        resources: BTreeMap::new(),
        payloads: BTreeMap::from([(
            options.runtime.executable.clone(),
            PayloadSource::File(options.helper_executable.clone()),
        )]),
        native: NativeInventory::default(),
        omissions: BTreeMap::new(),
        notices: String::from(
            "Lua helper: Lua 5.4/5.5, Copyright Lua.org, PUC-Rio; MIT license.\n",
        ),
        options: BTreeMap::from([
            ("language".to_owned(), "lua".to_owned()),
            ("lua.family".to_owned(), family.clone()),
            ("entry".to_owned(), entry),
        ]),
    };
    if project.join(".git").exists() {
        input
            .omissions
            .insert(".git/**".to_owned(), "version control metadata".to_owned());
    }
    let mut total = 0;
    for (relative, source) in files {
        if excluded(&relative, &options.exclusions) || relative == "glue.toml" {
            input.omissions.insert(
                relative,
                "build configuration or explicit exclusion".to_owned(),
            );
            continue;
        }
        insert(
            format!("app/{relative}"),
            source,
            &mut input,
            &mut total,
            limits,
        )?;
    }
    if let Some(tree) = &options.rocks_tree {
        let files = distribution::collect_tree(tree, options.output.as_deref(), max_files)?;
        let source_prefix = format!("share/lua/{family}/");
        let native_prefix = format!("lib/lua/{family}/");
        for (relative, source) in files {
            if let Some(module) = relative
                .strip_prefix(&source_prefix)
                .or_else(|| relative.strip_prefix(&native_prefix))
            {
                if excluded(module, &options.exclusions) {
                    input
                        .omissions
                        .insert(format!("rocks/{relative}"), "explicit exclusion".to_owned());
                    continue;
                }
                insert(
                    format!("app/{module}"),
                    source,
                    &mut input,
                    &mut total,
                    limits,
                )?;
            } else {
                input.omissions.insert(
                    format!("rocks/{relative}"),
                    "outside selected Lua module trees".to_owned(),
                );
            }
        }
    }
    for (logical, declared) in &options.native_abis {
        if !input.native.roots.contains_key(logical) {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                format!("native ABI declaration names unknown root {logical:?}"),
            ));
        }
        if declared != &family {
            return Err(error(
                DiagnosticCode::RuntimeAbiMismatch,
                format!("native root {logical:?} declares Lua {declared}, selected {family}"),
            ));
        }
        input
            .runtime
            .requirements
            .insert(format!("lua-native-abi:{logical}={declared}"));
        input
            .options
            .insert(format!("lua.native_abi.{logical}"), declared.clone());
    }
    Ok(input)
}

pub fn build(
    options: &LuaProjectOptions,
    launcher: &Path,
    output: &Path,
    limits: DistributionLimits,
) -> Result<glue_format::DistributionBuildReport, Diagnostic> {
    let mut options = options.clone();
    options.output = Some(output.to_owned());
    let mut input = ingest(&options, limits)?;
    resolve_native(&options, &mut input)?;
    distribution::build(input, launcher, output, limits)
}

/// Resolve the already-built native closure while preserving its deployed
/// layout. This can also be used by an integrator that publishes input itself.
pub fn resolve_native(
    options: &LuaProjectOptions,
    input: &mut DistributionInput,
) -> Result<(), Diagnostic> {
    use crate::native::{self, NativeRequest, NativeSearchRoot};
    use glue_format::DependencyProvider;
    use std::collections::BTreeSet;
    if input.native.roots.is_empty() {
        return Ok(());
    }
    let logical_roots = input.native.roots.clone();
    let mut images = Vec::new();
    let mut source_by_logical = BTreeMap::new();
    for (logical, deployed) in &logical_roots {
        let Some(PayloadSource::File(source)) = input.payloads.get(deployed) else {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                format!("native root {logical:?} lacks a file source"),
            ));
        };
        let canonical = fs::canonicalize(source)
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
        source_by_logical.insert(logical.clone(), canonical.clone());
        images.push(canonical);
    }
    let mut search_roots = vec![NativeSearchRoot {
        source: options.project.clone(),
        deployed: "native/lua".to_owned(),
        provider: DependencyProvider::Bundled,
    }];
    if let Some(tree) = &options.rocks_tree {
        let RuntimeAbi::Lua { version, .. } = options.runtime.abi else {
            unreachable!()
        };
        let native_tree = tree.join(format!("lib/lua/5.{}", version.minor));
        if native_tree.is_dir() {
            search_roots.push(NativeSearchRoot {
                source: native_tree,
                deployed: "native/lua".to_owned(),
                provider: DependencyProvider::Bundled,
            });
        }
    }
    for (index, root) in options.native_search.iter().enumerate() {
        search_roots.push(NativeSearchRoot {
            source: root.clone(),
            deployed: format!("native/search/{index}"),
            provider: DependencyProvider::Bundled,
        });
    }
    let collection = native::collect(&NativeRequest {
        images,
        search_roots,
        target: input.runtime.target.clone(),
        normalize: options.normalize_native_paths,
        host_libraries: BTreeSet::new(),
    })?;
    let secondary: BTreeSet<_> = collection
        .inventory
        .edges
        .iter()
        .filter(|edge| {
            matches!(
                edge.provider,
                DependencyProvider::Bundled | DependencyProvider::Runtime
            )
        })
        .map(|edge| edge.resolved.clone())
        .collect();
    let mut inventory = collection.inventory;
    inventory.roots.clear();
    for (logical, source) in source_by_logical {
        let deployed = collection.mappings.get(&source).ok_or_else(|| {
            error(
                DiagnosticCode::MissingDependency,
                "native scanner omitted an input image",
            )
        })?;
        if secondary.contains(deployed) && !options.native_abis.contains_key(&logical) {
            continue;
        }
        if !options.native_abis.contains_key(&logical) {
            return Err(error(
                DiagnosticCode::RuntimeAbiMismatch,
                format!(
                    "Lua native ABI cannot be inferred for {logical:?}; declare its selected Lua family explicitly"
                ),
            ));
        }
        inventory.roots.insert(logical, deployed.clone());
    }
    for deployed in logical_roots.values() {
        input.payloads.remove(deployed);
    }
    input.payloads.extend(collection.payloads);
    input.native = inventory;
    Ok(())
}
