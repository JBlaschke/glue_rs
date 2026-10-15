//! Stock subprocess provider. Runtime assembly happens only while building.
use super::failure::Failure;
use super::{
    discovery::{self, DiscoveryOptions, ResolvedEnvironment, read_bounded},
    inventory::{self, InventoryOptions},
};
use crate::{
    distribution::{self, DistributionInput, DistributionLimits, PayloadSource},
    native::{self, NativeRequest, NativeSearchRoot},
};
use glue_format::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Debug)]
pub struct CompactBuildOptions {
    pub discovery: DiscoveryOptions,
    pub application: InventoryOptions,
    pub runtime_provider: RuntimeProvider,
    pub native_search: Vec<PathBuf>,
    pub normalize_native_paths: bool,
    pub app_id: String,
}

pub fn build(
    options: &CompactBuildOptions,
    launcher: &Path,
    output: &Path,
) -> Result<DistributionBuildReport, Diagnostic> {
    build_with_options(options, launcher, output, &BTreeMap::new())
}
pub fn build_with_options(
    options: &CompactBuildOptions,
    launcher: &Path,
    output: &Path,
    context: &BTreeMap<String, String>,
) -> Result<DistributionBuildReport, Diagnostic> {
    build_impl(options, launcher, output, context).map_err(|e| e.0)
}
fn build_impl(
    options: &CompactBuildOptions,
    launcher: &Path,
    output: &Path,
    context: &BTreeMap<String, String>,
) -> Result<DistributionBuildReport, Failure> {
    let mut discovery = options.discovery.clone();
    let staged = if let Some(path) = &discovery.runtime {
        if path.is_file() && !is_native_file(path)? {
            if fs::metadata(path)
                .map_err(|e| Failure::new(DiagnosticCode::MissingInput, e.to_string()))?
                .len()
                > 1024 * 1024 * 1024
            {
                return Err(Failure::new(
                    DiagnosticCode::ResourceLimit,
                    "runtime archive exceeds 1 GiB compressed bound",
                ));
            }
            Some(
                materialize_runtime_archive(path)
                    .map_err(|e| Failure::new(DiagnosticCode::PayloadIntegrity, e))?,
            )
        } else {
            None
        }
    } else {
        None
    };
    if let Some(staged) = &staged {
        discovery.runtime = Some(staged.runtime_root()?);
    }
    let mut environment = discovery::discover_diagnostic(&discovery)?;
    if let Some(staged) = &staged {
        environment
            .descriptor
            .inputs
            .insert("runtime-archive".into(), staged.1.clone());
    }
    let mut input = prepare(options, &environment, output)?;
    let mut context = context.clone();
    if let Some(expected) = context.remove("glue.expected-runtime") {
        let expected: RuntimeDescriptor = serde_json::from_str(&expected).map_err(|e| {
            Failure::new(
                DiagnosticCode::InvalidConfiguration,
                format!("invalid expected runtime descriptor: {e}"),
            )
        })?;
        let actual = &input.runtime;
        if expected.implementation != actual.implementation
            || expected.provider != actual.provider
            || expected.version != actual.version
            || expected.abi != actual.abi
            || expected.target != actual.target
            || expected.inputs != actual.inputs
        {
            return Err(Failure::new(
                DiagnosticCode::PayloadIntegrity,
                "selected Python runtime differs from the recorded rebuild lock",
            ));
        }
    }
    input.options.extend(context);
    distribution::build(input, launcher, output, DistributionLimits::default())
        .map_err(Failure::from)
}

pub fn prepare(
    options: &CompactBuildOptions,
    environment: &ResolvedEnvironment,
    output: &Path,
) -> Result<DistributionInput, Diagnostic> {
    prepare_impl(options, environment, output).map_err(|e| e.0)
}
fn prepare_impl(
    options: &CompactBuildOptions,
    environment: &ResolvedEnvironment,
    output: &Path,
) -> Result<DistributionInput, Failure> {
    let mut application = options.application.clone();
    application.output = Some(output.to_owned());
    let mut application = inventory::collect_diagnostic(environment, &application)?;
    super::native::validate(&application, environment)?;
    super::native::validate_runtime_linkage(environment, &application.native_files)?;
    let mut descriptor = environment.descriptor.clone();
    descriptor.provider = options.runtime_provider;
    let mut payloads = BTreeMap::new();
    let mut native = NativeInventory::default();
    let mut omissions = application.omissions;
    if options.runtime_provider == RuntimeProvider::Bundled {
        let root = fs::canonicalize(&environment.runtime.prefix)
            .map_err(|e| Failure::new(DiagnosticCode::MissingInput, e.to_string()))?;
        let stdlib = fs::canonicalize(&environment.runtime.stdlib)
            .map_err(|e| Failure::new(DiagnosticCode::MissingInput, e.to_string()))?;
        if !stdlib.starts_with(&root) {
            return Err(Failure::new(
                DiagnosticCode::PathEscape,
                "selected stdlib escapes selected runtime prefix",
            ));
        }
        let (files, runtime_omissions) = inventory::runtime_stdlib_files(&root, &stdlib)?;
        omissions.extend(
            runtime_omissions
                .into_iter()
                .map(|(path, reason)| (format!("runtime/{path}"), reason)),
        );
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let zip_options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6))
            .unix_permissions(0o444)
            .last_modified_time(zip::DateTime::default());
        let mut images = vec![environment.runtime.executable.clone()];
        let mut runtime_seeds = images.clone();
        images.extend(application.native_files.values().cloned());
        let mut bytes = 0u64;
        let mut entries = 0usize;
        for (relative, path) in files {
            let Some(relative_stdlib) = Path::new(&relative)
                .strip_prefix(stdlib.strip_prefix(&root).map_err(|e| e.to_string())?)
                .ok()
            else {
                continue;
            };
            let name = relative_stdlib
                .to_str()
                .ok_or("non-UTF8 stdlib path")?
                .replace('\\', "/");
            if name
                .split('/')
                .any(|p| p == "site-packages" || p == "__pycache__")
                || name.ends_with(".pyc")
                || name.ends_with(".pyo")
            {
                omissions.insert(
                    format!("runtime/{relative}"),
                    "runtime_site_or_bytecode_not_bootstrap".into(),
                );
                continue;
            }
            if is_native_file(&path)? {
                if name.starts_with("lib-dynload/") {
                    runtime_seeds.push(path.clone());
                    images.push(path);
                }
                continue;
            }
            if name.ends_with(".a") || name.ends_with(".h") || name.ends_with(".pc") {
                omissions.insert(
                    format!("runtime/{relative}"),
                    "development_only_runtime_input".into(),
                );
                continue;
            }
            ResourcePath::new(&name).map_err(|e| e.to_string())?;
            let data = read_bounded(&path, 64 * 1024 * 1024)?;
            bytes = bytes
                .checked_add(data.len() as u64)
                .ok_or("stdlib bytes overflow")?;
            if bytes > 1024 * 1024 * 1024 {
                return Err(Failure::new(
                    DiagnosticCode::ResourceLimit,
                    "stdlib archive exceeds 1 GiB input bound",
                ));
            }
            descriptor
                .inputs
                .insert(format!("stdlib:{name}"), InputIdentity::of(&data));
            zip.start_file(&name, zip_options)
                .map_err(|e| e.to_string())?;
            zip.write_all(&data).map_err(|e| e.to_string())?;
            entries += 1;
        }
        if entries == 0 {
            return Err("selected stdlib has no source/data entries".into());
        }
        let stdlib_zip = zip.finish().map_err(|e| e.to_string())?.into_inner();
        let mut roots = vec![NativeSearchRoot {
            source: root.clone(),
            deployed: "runtime".into(),
            provider: DependencyProvider::Runtime,
        }];
        if root.join("lib").is_dir() {
            roots.push(NativeSearchRoot {
                source: root.join("lib"),
                deployed: "runtime/lib".into(),
                provider: DependencyProvider::Runtime,
            });
        }
        if !environment.runtime.framework.is_empty() {
            // The stock real framework executable runs without a .app container.
            // Deploy it as a standalone signed image so final codesign validation
            // does not infer a bundle resource envelope absent from compact mode.
            roots.push(NativeSearchRoot {
                source: environment
                    .runtime
                    .executable
                    .parent()
                    .ok_or("framework interpreter has no directory")?
                    .to_owned(),
                deployed: "runtime/bin".into(),
                provider: DependencyProvider::Runtime,
            });
        }
        roots.extend(super::native::search_roots(
            environment,
            &options.application.project,
        )?);
        for (index, source) in options.native_search.iter().enumerate() {
            roots.push(NativeSearchRoot {
                source: source.clone(),
                deployed: format!("native/search{index}"),
                provider: DependencyProvider::Bundled,
            });
        }
        let closure = native::collect(&NativeRequest {
            images,
            search_roots: roots,
            target: descriptor.target.clone(),
            normalize: options.normalize_native_paths,
            host_libraries: BTreeSet::new(),
        })?;
        descriptor
            .inputs
            .extend(super::native::runtime_input_identities(
                &runtime_seeds,
                &closure,
            )?);
        descriptor.executable = closure
            .mappings
            .get(&fs::canonicalize(&environment.runtime.executable).map_err(|e| e.to_string())?)
            .cloned()
            .ok_or("runtime executable missing from collected closure")?;
        application.index.native =
            super::native::mappings(&application.native_files, &closure.mappings)?;
        native = closure.inventory;
        payloads = closure.payloads;
        payloads.insert(
            format!(
                "runtime/lib/python{}{}.zip",
                environment.runtime.version[0], environment.runtime.version[1]
            ),
            PayloadSource::Bytes {
                bytes: stdlib_zip,
                mode: 0o444,
            },
        );
        descriptor
            .requirements
            .extend(native.host_requirements.iter().cloned());
        descriptor
            .requirements
            .insert("Tcl/Tk external script data requires a separate resource adapter".into());
    } else {
        descriptor.executable = environment
            .runtime
            .executable
            .to_string_lossy()
            .into_owned();
        descriptor.requirements.insert(format!(
            "explicit host CPython {} at {}",
            descriptor.version, descriptor.executable
        ));
        if !application.native_files.is_empty() {
            let mut roots = super::native::search_roots(environment, &options.application.project)?;
            for (index, source) in options.native_search.iter().enumerate() {
                roots.push(NativeSearchRoot {
                    source: source.clone(),
                    deployed: format!("native/search{index}"),
                    provider: DependencyProvider::Bundled,
                });
            }
            let host_libraries = crate::native::inspect(&environment.runtime.executable)?
                .dependencies
                .into_iter()
                .filter(|name| name.contains("libpython") || name.ends_with("/Python"))
                .collect();
            let closure = native::collect(&NativeRequest {
                images: application.native_files.values().cloned().collect(),
                search_roots: roots,
                target: descriptor.target.clone(),
                normalize: options.normalize_native_paths,
                host_libraries,
            })?;
            application.index.native =
                super::native::mappings(&application.native_files, &closure.mappings)?;
            native = closure.inventory;
            payloads = closure.payloads;
            descriptor
                .requirements
                .extend(native.host_requirements.iter().cloned());
        }
    }
    application.resources.insert(
        "support/python-index.json".into(),
        serde_json::to_vec(&application.index).map_err(|e| e.to_string())?,
    );
    let bootstrap = bootstrap(environment, options.runtime_provider);
    payloads.insert(
        "support/python-bootstrap.py".into(),
        PayloadSource::Bytes {
            bytes: bootstrap.into_bytes(),
            mode: 0o444,
        },
    );
    let mut configuration = BTreeMap::new();
    configuration.insert(
        "python.environment".into(),
        options.discovery.environment.to_string_lossy().into_owned(),
    );
    configuration.insert(
        "python.project".into(),
        options.application.project.to_string_lossy().into_owned(),
    );
    configuration.insert(
        "python.entry".into(),
        serde_json::to_string(&options.application.entry).map_err(|e| e.to_string())?,
    );
    if let Some(runtime) = &options.discovery.runtime {
        configuration.insert(
            "python.runtime".into(),
            runtime.to_string_lossy().into_owned(),
        );
    }
    configuration.insert(
        "python.unowned_files".into(),
        serde_json::to_string(&application.unowned).map_err(|e| e.to_string())?,
    );
    let mut notices = String::from(
        "Python runtime/package notices remain in the declared archived source/metadata inventory.\n",
    );
    for (path, bytes) in &application.resources {
        if path.to_ascii_lowercase().contains("license")
            || path.to_ascii_lowercase().contains("notice")
        {
            notices.push_str(&format!(
                "\n--- {path} ---\n{}\n",
                String::from_utf8_lossy(bytes)
            ));
        }
    }
    Ok(DistributionInput {
        app_id: options.app_id.clone(),
        entrypoint: "support/python-index.json".into(),
        runtime: descriptor.clone(),
        launch: RuntimeLaunchSpec {
            executable: descriptor.executable,
            args: vec![
                "-I".into(),
                "-S".into(),
                "-B".into(),
                "{root}/support/python-bootstrap.py".into(),
                "{archive}".into(),
            ],
            environment: BTreeMap::from([
                ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
                ("PYTHONNOUSERSITE".into(), "1".into()),
            ]),
            clear_environment: true,
        },
        resources: application.resources,
        payloads,
        native,
        omissions,
        notices,
        options: configuration,
    })
}

fn bootstrap(environment: &ResolvedEnvironment, provider: RuntimeProvider) -> String {
    let exact = environment
        .runtime
        .version_text
        .split_whitespace()
        .next()
        .unwrap_or("");
    let prefix = format!(
        r#"import os, sys
if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    raise RuntimeError("compact Python requires -I -S -B")
if tuple(sys.version_info[:3]) != ({}, {}, {}):
    raise RuntimeError("selected Python runtime version differs before application execution")
if sys.version.split()[0] != {exact:?}:
    raise RuntimeError("selected Python prerelease/build version differs")
distribution = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
"#,
        environment.runtime.version[0],
        environment.runtime.version[1],
        environment.runtime.version[2]
    );
    let bundled = if provider == RuntimeProvider::Bundled {
        r#"runtime = os.path.join(distribution, "runtime")
for path in sys.path:
    if os.path.commonpath([runtime, os.path.realpath(path)]) != runtime:
        raise RuntimeError("runtime prefix fallback outside distribution: " + path)
import encodings
if encodings.__spec__.origin == "frozen":
    stdlib_zip = next((path for path in sys.path if path.endswith(".zip")), None)
    if stdlib_zip is None:
        raise RuntimeError("frozen encodings package requires archived stdlib")
    encodings.__path__ = [stdlib_zip + "/encodings"]
    encodings.__spec__.submodule_search_locations = encodings.__path__
"#
    } else {
        ""
    };
    format!(
        "{prefix}{bundled}\n{}\nrun_application(os.path.realpath(sys.argv[1]), distribution, sys.argv[2:])\n",
        include_str!("importer.py")
    )
}

fn is_native_file(path: &Path) -> Result<bool, String> {
    use std::io::Read;
    let mut prefix = [0u8; 4];
    let count = File::open(path)
        .map_err(|e| e.to_string())?
        .read(&mut prefix)
        .map_err(|e| e.to_string())?;
    Ok(count == 4
        && [
            b"\x7fELF",
            &[0xcf, 0xfa, 0xed, 0xfe],
            &[0xca, 0xfe, 0xba, 0xbe],
            &[0xca, 0xfe, 0xba, 0xbf],
        ]
        .contains(&&prefix))
}

struct RuntimeStage(PathBuf, InputIdentity);
impl Drop for RuntimeStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl RuntimeStage {
    fn runtime_root(&self) -> Result<PathBuf, String> {
        for path in [
            self.0.join("python/install"),
            self.0.join("python"),
            self.0.clone(),
        ] {
            if path.join("bin").is_dir() {
                return Ok(path);
            }
        }
        Err("PBS archive has no installed runtime tree".into())
    }
}
fn materialize_runtime_archive(path: &Path) -> Result<RuntimeStage, String> {
    let original_identity = InputIdentity::of(&read_bounded(path, 1024 * 1024 * 1024)?);
    let inventory = discovery::inspect_pbs_archive(path)?;
    let prefix = if inventory
        .entries
        .keys()
        .any(|p| p.starts_with("python/install/bin/"))
    {
        "python/install/"
    } else {
        "python/"
    };
    let selection = inventory
        .entries
        .iter()
        .filter(|(name, entry)| {
            entry.kind == glue_pbs::archive::EntryKind::RegularFile
                && name.starts_with(prefix)
                && !name.ends_with(".a")
                && !name.contains("/include/")
                && !name.contains(".dSYM/")
        })
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let mut batches = Vec::new();
    let mut batch = BTreeSet::new();
    let mut batch_bytes = 0u64;
    let mut total_bytes = 0u64;
    for name in &selection {
        let size = inventory.entries[name].size;
        if size > glue_pbs::archive::MAX_SELECTED_BYTES {
            return Err(
                "one runtime archive member exceeds the 128 MiB retained-member bound".into(),
            );
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or("runtime selection overflow")?;
        if total_bytes > 1024 * 1024 * 1024 {
            return Err(
                "selected runtime archive bytes exceed the 1 GiB staged-input bound".into(),
            );
        }
        if batch_bytes + size > glue_pbs::archive::MAX_SELECTED_BYTES {
            batches.push(std::mem::take(&mut batch));
            batch_bytes = 0;
        }
        batch.insert(name.clone());
        batch_bytes += size;
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    let reader = || -> Result<Box<dyn io::Read>, String> {
        let source = io::BufReader::new(File::open(path).map_err(|e| e.to_string())?);
        let mut head = File::open(path).map_err(|e| e.to_string())?;
        let mut magic = [0u8; 4];
        use std::io::Read;
        head.read_exact(&mut magic).map_err(|e| e.to_string())?;
        if magic[..2] == [0x1f, 0x8b] {
            Ok(Box::new(flate2::read::GzDecoder::new(source)))
        } else if magic == [0x28, 0xb5, 0x2f, 0xfd] {
            Ok(Box::new(
                ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                    source,
                    128 * 1024 * 1024,
                )
                .map_err(|e| e.to_string())?,
            ))
        } else {
            Ok(Box::new(source))
        }
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stage = loop {
        let candidate = std::env::temp_dir().join(format!(
            "glue-python-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break RuntimeStage(candidate, original_identity),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    };
    // Keep the selective reader's 128 MiB memory ceiling while staging larger
    // ordinary full/install-only runtimes in bounded, independently validated passes.
    for batch in &batches {
        let selected = glue_pbs::archive::read_selected(
            reader()?,
            &glue_pbs::archive::Limits::default(),
            batch,
            glue_pbs::archive::MAX_SELECTED_BYTES,
        )?;
        if selected.inventory != inventory {
            return Err("runtime archive changed during bounded selection".into());
        }
        for (name, bytes) in &selected.files {
            let dest = stage.0.join(name);
            fs::create_dir_all(dest.parent().ok_or("runtime input has no parent")?)
                .map_err(|e| e.to_string())?;
            fs::write(&dest, bytes).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &dest,
                    fs::Permissions::from_mode(selected.inventory.entries[name].mode & 0o777),
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    if InputIdentity::of(&read_bounded(path, 1024 * 1024 * 1024)?) != stage.1 {
        return Err("runtime archive changed during build-time inspection".into());
    }
    // Resolve already-validated aliases after writing regular files. Materialized
    // aliases point to regular selected bytes; none can redirect later writes.
    for (name, entry) in &inventory.entries {
        if name.starts_with(prefix)
            && matches!(
                entry.kind,
                glue_pbs::archive::EntryKind::Symlink | glue_pbs::archive::EntryKind::Hardlink
            )
        {
            if let Some(target) = &entry.resolved_target {
                if selection.contains(target) {
                    let dest = stage.0.join(name);
                    fs::create_dir_all(dest.parent().ok_or("runtime alias has no parent")?)
                        .map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    {
                        let parent =
                            fs::canonicalize(dest.parent().ok_or("runtime alias has no parent")?)
                                .map_err(|e| e.to_string())?;
                        let actual =
                            fs::canonicalize(stage.0.join(target)).map_err(|e| e.to_string())?;
                        std::os::unix::fs::symlink(native::relative_path(&parent, &actual), &dest)
                            .map_err(|e| e.to_string())?;
                    }
                }
            }
        }
    }
    Ok(stage)
}
