//! Execution of pinned stock PBS Python source applications and fixture profiles.
//!
//! This crate supports a bounded GNU Linux arm64 source-application contract,
//! exact fixture profiles and the explicit macOS arm64 host startup profile.
//! Provider handles remain pinned for process life; the synchronous executor
//! owns one interpreter lifecycle.
#![deny(unsafe_code)]

pub mod packaging;
#[allow(unsafe_code)]
mod platform;
pub mod profile;

mod bundle;
mod extension_profile;
mod host;
mod host_import_profile;
mod host_source_app_profile;
mod import_profile;
#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
mod imports;
mod install_host_source_app_profile;
#[cfg(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu",
    glue_python_boundary
))]
#[allow(unsafe_code)]
mod linux;
#[cfg(glue_python_macos_host)]
#[allow(unsafe_code)]
mod macos;
mod macos_host;
mod metadata_profile;
mod source_app_profile;
mod source_entry;
mod stripped_host;

use bundle::Bundle;
use glue_format::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

const LIBRARY_MEMBER: &str = "python/install/lib/libpython3.13.so.1.0";
const LIBRARY: &str = "python/libpython3.13.so.1.0";
const STDLIB: &str = "python/frozen.json";
const APP: &str = "app/main.py";
const LIBRARY_SHA: &str = "42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219";
const LIBRARY_SIZE: u64 = 73_563_968;
const BUNDLE_LIMIT: u64 = 4 * 1024 * 1024;
const PINS: &[u8] = include_bytes!("../../../fixtures/python-pbs/pins.json");
const HOST_APP: &[u8] = include_bytes!("../../../fixtures/python-bootstrap/app.py");

/// An unavailable capability or a failed controlled-profile execution.
#[derive(Debug)]
pub struct ExecutionError {
    message: String,
    unsupported: bool,
}

impl ExecutionError {
    /// Preserve unsupported capability status separately from invalid input,
    /// integrity failures and application errors.
    pub fn is_unsupported(&self) -> bool {
        self.unsupported
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unsupported: false,
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unsupported: true,
        }
    }
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ExecutionError {}

/// Run one admitted pinned profile from its already-open archive.
///
/// All archive resources verify before provider loading. The private C boundary
/// owns Python objects and runs initialization, execution and finalization on
/// this calling thread. Loaded provider mappings remain pinned for process life;
/// this is not a restartable or concurrent interpreter API.
pub fn execute(
    archive: Archive<File>,
    selected: profile::ControlledProfile,
) -> Result<(), ExecutionError> {
    if archive.manifest() != &selected.manifest {
        return Err(ExecutionError::failed(
            "controlled Python profile belongs to another manifest",
        ));
    }
    let verified = profile::validate(archive.manifest())?;
    if verified.kind != selected.kind {
        return Err(ExecutionError::failed(
            "controlled Python profile selection changed",
        ));
    }
    profile::readiness(&selected)?;
    #[cfg(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ))]
    {
        match selected.kind {
            profile::Kind::MacosHostStartup => {
                drop(archive);
                return Err(ExecutionError::unsupported(
                    "the explicit macOS host Python startup profile requires macOS arm64",
                ));
            }
            profile::Kind::BundledMetadataApp => linux::run_imports(
                metadata_profile::read_bundled(archive).map_err(ExecutionError::failed)?,
                None,
                false,
            ),
            profile::Kind::HostMetadataApp => linux::run_host_source_app(
                metadata_profile::read_host(archive).map_err(ExecutionError::failed)?,
            ),
            profile::Kind::InstallHostMetadataApp => linux::run_install_host_source_app(
                metadata_profile::read_install_host(archive).map_err(ExecutionError::failed)?,
            ),
            profile::Kind::StrippedInstallHostMetadataApp => {
                linux::run_stripped_install_host_metadata_app(
                    metadata_profile::read_stripped_install_host(archive)
                        .map_err(ExecutionError::failed)?,
                )
            }
            profile::Kind::InstallHostSourceApp => linux::run_install_host_source_app(
                install_host_source_app_profile::read_archive(archive)
                    .map_err(ExecutionError::failed)?,
            ),
            profile::Kind::HostSourceApp => linux::run_host_source_app(
                host_source_app_profile::read_archive(archive).map_err(ExecutionError::failed)?,
            ),
            profile::Kind::BundledSourceApp => linux::run_imports(
                source_app_profile::read_archive(archive).map_err(ExecutionError::failed)?,
                None,
                false,
            ),
            profile::Kind::BundledImports => linux::run_imports(
                import_profile::read_archive(archive).map_err(ExecutionError::failed)?,
                None,
                false,
            ),
            profile::Kind::HostImports => linux::run_host_imports(
                host_import_profile::read_archive(archive).map_err(ExecutionError::failed)?,
                false,
            ),
            profile::Kind::RegisteredExtensions => linux::run_extensions(
                extension_profile::read_archive(archive).map_err(ExecutionError::failed)?,
                false,
            ),
            profile::Kind::NativeLifecycle => linux::run_extensions(
                extension_profile::read_archive_for(extension_profile::Profile::Lifecycle, archive)
                    .map_err(ExecutionError::failed)?,
                false,
            ),
            profile::Kind::NativePackages => linux::run_extensions(
                extension_profile::read_archive_for(
                    extension_profile::Profile::PackageImports,
                    archive,
                )
                .map_err(ExecutionError::failed)?,
                false,
            ),
        }
        .map_err(ExecutionError::failed)
    }
    #[cfg(glue_python_macos_host)]
    {
        match selected.kind {
            profile::Kind::MacosHostStartup => macos::run_host(
                macos_host::read_payload_from(archive).map_err(ExecutionError::failed)?,
                false,
            )
            .map_err(ExecutionError::failed),
            _ => {
                drop(archive);
                Err(ExecutionError::unsupported(
                    "this Python profile executes only with pbs-bootstrap on GNU Linux arm64",
                ))
            }
        }
    }
    #[cfg(not(any(
        all(
            feature = "pbs-bootstrap",
            target_os = "linux",
            target_arch = "aarch64",
            target_env = "gnu",
            glue_python_boundary
        ),
        glue_python_macos_host
    )))]
    {
        drop(archive);
        Err(ExecutionError::unsupported(
            "execution requires pbs-bootstrap on GNU Linux arm64",
        ))
    }
}

/// Fixture preparation and fault-injection scaffold used by the existing probe.
/// Product execution uses the controlled profile facade above.
pub mod experimental {
    use super::*;

    /// Dispatch the historical probe arguments, including the executable name.
    pub fn dispatch(args: &[std::ffi::OsString]) -> Result<(), ExecutionError> {
        #[cfg(not(all(
            feature = "pbs-bootstrap",
            target_os = "linux",
            target_arch = "aarch64",
            target_env = "gnu",
            glue_python_boundary
        )))]
        if args
            .get(1)
            .and_then(|value| value.to_str())
            .is_some_and(|mode| {
                matches!(
                    mode,
                    "run"
                        | "baseline"
                        | "run-negative"
                        | "run-host"
                        | "run-host-negative"
                        | "run-imports"
                        | "baseline-imports"
                        | "run-imports-negative"
                        | "run-host-imports"
                        | "run-host-imports-negative"
                        | "run-extensions"
                        | "run-extensions-negative"
                        | "run-native-lifecycle"
                        | "run-native-lifecycle-negative"
                        | "run-native-packages"
                        | "run-native-packages-negative"
                )
            })
        {
            return Err(ExecutionError::unsupported(
                "execution requires pbs-bootstrap on GNU Linux arm64",
            ));
        }
        #[cfg(not(glue_python_macos_host))]
        if args
            .get(1)
            .and_then(|value| value.to_str())
            .is_some_and(|mode| matches!(mode, "run-host-macos" | "run-host-macos-negative"))
        {
            return Err(ExecutionError::unsupported(
                "execution requires pbs-bootstrap with a verified header tree on macOS arm64",
            ));
        }
        dispatch_experiment(args).map_err(ExecutionError::failed)
    }
}

fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_entry_bytes: 80 * 1024 * 1024,
        max_archive_bytes: 84 * 1024 * 1024,
        max_total_uncompressed_bytes: 84 * 1024 * 1024,
        max_entries: 3,
        max_central_directory_bytes: 8192,
        ..ArchiveLimits::default()
    }
}

fn manifest(resources: BTreeMap<String, ResourceSpec>) -> Result<Manifest, String> {
    profile_manifest(resources, None)
}

fn profile_manifest(
    resources: BTreeMap<String, ResourceSpec>,
    host: Option<&host::Config>,
) -> Result<Manifest, String> {
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let provisioning = if let Some(config) = host {
        Provisioning::Host {
            runtime_library: config.library.clone(),
            stdlib: config.stdlib.clone(),
            discovery: HostDiscovery::ExplicitPaths,
        }
    } else {
        Provisioning::Bundled {
            provider: BundledProvider::PythonBuildStandalone,
            source: SourcePin {
                release: pins.release,
                revision: Some(pins.revision),
                artifact: pins.full.filename,
                sha256: pins.full.sha256,
                variant: "pgo+lto-full/frozen-startup-v1".into(),
            },
            runtime_library: LIBRARY.into(),
            stdlib: STDLIB.into(),
        }
    };
    let result = Manifest {
        distribution: None,
        schema_version: 0,
        app_id: if host.is_some() {
            "stock-pbs-host-startup"
        } else {
            "stock-pbs-bootstrap"
        }
        .into(),
        entrypoint: "main".into(),
        targets: BTreeMap::from([(
            "linux-arm64".into(),
            TargetProfile {
                os: OperatingSystem::Linux,
                arch: Architecture::Aarch64,
                // Observed test cell, not an inferred upstream compatibility floor.
                minimum_os_version: "7.1.4".into(),
                abi: TargetAbi::Glibc {
                    minimum_version: "2.36".into(),
                },
                page_sizes: BTreeSet::from([4096]),
                cpu_features: BTreeSet::new(),
            },
        )]),
        resources,
        runtimes: BTreeMap::from([(
            "python".into(),
            RuntimeSpec {
                target: "linux-arm64".into(),
                build_id: if host.is_some() {
                    "pbs-20261009-cpython-3.13.16-pgo-lto-host-startup-v1"
                } else {
                    "pbs-20261009-cpython-3.13.16-pgo-lto-frozen-bootstrap-v1"
                }
                .into(),
                abi: RuntimeAbi::Python {
                    version: RuntimeVersion {
                        major: 3,
                        minor: 13,
                        patch: 16,
                    },
                    gil: GilMode::Conventional,
                    debug: false,
                },
                provisioning,
                required_features: BTreeSet::new(),
            },
        )]),
        components: BTreeMap::from([(
            "main".into(),
            ComponentSpec {
                runtime: "python".into(),
                entry_point: APP.into(),
                native_modules: BTreeSet::new(),
            },
        )]),
        native_modules: BTreeMap::new(),
        host_imports: BTreeMap::new(),
    };
    result.validate().map_err(|e| e.to_string())?;
    Ok(result)
}

fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("input exceeds bounded fixture limit".into());
    }
    Ok(bytes)
}

fn prepare(full: &Path, bundle_path: &Path, output: &Path) -> Result<(), String> {
    let bundle_bytes = bounded_file(bundle_path, BUNDLE_LIMIT)?;
    let bundle = Bundle::parse(&bundle_bytes)?;
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let mut selected = glue_pbs::inspect_full_selected(
        &pins,
        &mut File::open(full).map_err(|e| e.to_string())?,
        &BTreeSet::from([LIBRARY_MEMBER.into()]),
        128 * 1024 * 1024,
    )?;
    bundle.validate_sources(&selected.inspection)?;
    let library = selected
        .files
        .remove(LIBRARY_MEMBER)
        .ok_or("missing selected library")?;
    check_library(&library)?;
    let resources: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        (LIBRARY.into(), library),
        (STDLIB.into(), bundle_bytes),
        (APP.into(), bundle.app.decode_hex()?),
    ]);
    let specs = resources
        .iter()
        .map(|(key, bytes)| {
            (
                key.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression: Compression::Stored,
                },
            )
        })
        .collect();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &manifest(specs)?, &resources).map_err(|e| e.to_string())?;
    println!("prepared stock PBS frozen bootstrap archive");
    Ok(())
}

fn check_library(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 != LIBRARY_SIZE || digest(bytes) != LIBRARY_SHA {
        return Err("stock PBS runtime library identity mismatch".into());
    }
    Ok(())
}

fn host_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_entry_bytes: 65536,
        max_archive_bytes: 96 * 1024,
        max_total_uncompressed_bytes: 65536,
        max_entries: 1,
        max_central_directory_bytes: 8192,
        ..ArchiveLimits::default()
    }
}

fn prepare_host(
    full: &Path,
    bundle_path: &Path,
    prefix: &str,
    output: &Path,
) -> Result<(), String> {
    let config = host::Config::parse(prefix)?;
    let bundle = Bundle::parse(&bounded_file(bundle_path, BUNDLE_LIMIT)?)?;
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let inspection = glue_pbs::inspect(
        &pins,
        &mut File::open(full).map_err(|e| e.to_string())?,
        None,
    )?;
    bundle.validate_sources(&inspection)?;
    let app = bundle.app.decode_hex()?;
    if app != HOST_APP {
        return Err("host startup app differs from the shared compiled fixture".into());
    }
    let resources = BTreeMap::from([(APP.into(), app)]);
    let specs = BTreeMap::from([(
        APP.into(),
        ResourceSpec {
            size: HOST_APP.len() as u64,
            sha256: digest(HOST_APP),
            compression: Compression::Stored,
        },
    )]);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &profile_manifest(specs, Some(&config))?, &resources)
        .map_err(|e| e.to_string())?;
    println!("prepared explicit host Python startup archive");
    Ok(())
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
struct HostPayload {
    config: host::Config,
    app: Vec<u8>,
}

fn admit_host_manifest(actual: &Manifest) -> Result<host::Config, String> {
    let runtime = actual
        .runtimes
        .get("python")
        .ok_or("missing host Python runtime")?;
    let Provisioning::Host {
        runtime_library,
        stdlib,
        discovery: HostDiscovery::ExplicitPaths,
    } = &runtime.provisioning
    else {
        return Err("archive differs from the explicit host Python fixture profile".into());
    };
    let prefix = stdlib
        .strip_suffix("/lib/python3.13")
        .ok_or("host stdlib does not use the fixed installation layout")?;
    let config = host::Config::parse(prefix)?;
    if *runtime_library != config.library || *stdlib != config.stdlib {
        return Err("host library and stdlib installation paths disagree".into());
    }
    let specs = BTreeMap::from([(
        APP.into(),
        ResourceSpec {
            size: HOST_APP.len() as u64,
            sha256: digest(HOST_APP),
            compression: Compression::Stored,
        },
    )]);
    if *actual != profile_manifest(specs, Some(&config))? {
        return Err("archive differs from the explicit host Python fixture profile".into());
    }
    Ok(config)
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
fn read_host_payload(path: &Path) -> Result<HostPayload, String> {
    let mut archive =
        Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, host_limits())
            .map_err(|e| e.to_string())?;
    let config = admit_host_manifest(archive.manifest())?;
    if archive
        .entries()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from([APP])
    {
        return Err("host fixture contains unexpected archive payloads".into());
    }
    let app = archive.read_resource(APP).map_err(|e| e.to_string())?;
    if app != HOST_APP {
        return Err("host startup app differs from the shared compiled fixture".into());
    }
    Ok(HostPayload { config, app })
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
struct Payload {
    library: Vec<u8>,
    bundle: Bundle,
    app: Vec<u8>,
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
fn read_payload(path: &Path) -> Result<Payload, String> {
    let mut archive =
        Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, limits())
            .map_err(|e| e.to_string())?;
    admit_manifest(archive.manifest())?;
    if archive
        .entries()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from([APP, LIBRARY, STDLIB])
    {
        return Err("archive differs from the stock PBS fixture profile".into());
    }
    if archive.manifest().resources[STDLIB].size > BUNDLE_LIMIT
        || archive.manifest().resources[APP].size > 65536
    {
        return Err("bootstrap bundle or app exceeds its byte limit".into());
    }
    // All resources verify before loading code or entering the C boundary.
    let library = archive.read_resource(LIBRARY).map_err(|e| e.to_string())?;
    check_library(&library)?;
    let bundle = Bundle::parse(&archive.read_resource(STDLIB).map_err(|e| e.to_string())?)?;
    let app = archive.read_resource(APP).map_err(|e| e.to_string())?;
    if app != bundle.app.decode_hex()? {
        return Err("app disagrees with verified freeze bundle".into());
    }
    Ok(Payload {
        library,
        bundle,
        app,
    })
}

fn admit_manifest(actual: &Manifest) -> Result<(), String> {
    if *actual != manifest(actual.resources.clone())?
        || actual
            .resources
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from([APP, LIBRARY, STDLIB])
    {
        return Err("archive differs from the stock PBS fixture profile".into());
    }
    let library = &actual.resources[LIBRARY];
    if library.size != LIBRARY_SIZE || library.sha256 != LIBRARY_SHA {
        return Err("stock PBS runtime resource identity mismatch".into());
    }
    Ok(())
}

fn dispatch_experiment(args: &[std::ffi::OsString]) -> Result<(), String> {
    let mode = args.get(1).and_then(|s| s.to_str()).unwrap_or("");
    if mode == "prepare-host-macos" && args.len() == 5 {
        return macos_host::prepare(
            Path::new(&args[2]),
            args[3].to_str().unwrap_or(""),
            Path::new(&args[4]),
        );
    }
    if matches!(mode, "run-host-macos" | "run-host-macos-negative") {
        let negative = mode == "run-host-macos-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong macOS host fixture arguments".into());
        }
        return run_host_macos(macos_host::read_payload(Path::new(&args[2]))?, negative);
    }
    if mode == "prepare" && args.len() == 5 {
        prepare(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        )
    } else if mode == "prepare-host" && args.len() == 6 {
        prepare_host(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap_or(""),
            Path::new(&args[5]),
        )
    } else if mode == "prepare-imports" && args.len() == 5 {
        import_profile::prepare(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        )
    } else if mode == "corrupt-imports" && args.len() == 4 {
        import_profile::corrupt(Path::new(&args[2]), Path::new(&args[3]))
    } else if mode == "prepare-host-imports" && args.len() == 5 {
        host_import_profile::prepare(
            Path::new(&args[2]),
            args[3].to_str().unwrap_or(""),
            Path::new(&args[4]),
        )
    } else if mode == "prepare-extensions" && args.len() == 6 {
        extension_profile::prepare(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap_or(""),
            Path::new(&args[5]),
        )
    } else if mode == "prepare-native-lifecycle" && args.len() == 6 {
        extension_profile::prepare_for(
            extension_profile::Profile::Lifecycle,
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap_or(""),
            Path::new(&args[5]),
        )
    } else if mode == "prepare-native-packages" && args.len() == 6 {
        extension_profile::prepare_for(
            extension_profile::Profile::PackageImports,
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap_or(""),
            Path::new(&args[5]),
        )
    } else if mode == "corrupt-native-packages" && args.len() == 4 {
        extension_profile::corrupt_for(
            extension_profile::Profile::PackageImports,
            Path::new(&args[2]),
            Path::new(&args[3]),
        )
    } else if mode == "corrupt-native-lifecycle" && args.len() == 4 {
        extension_profile::corrupt_for(
            extension_profile::Profile::Lifecycle,
            Path::new(&args[2]),
            Path::new(&args[3]),
        )
    } else if mode == "corrupt-extensions" && args.len() == 4 {
        extension_profile::corrupt(Path::new(&args[2]), Path::new(&args[3]))
    } else if mode == "corrupt-host-imports" && args.len() == 4 {
        host_import_profile::corrupt(Path::new(&args[2]), Path::new(&args[3]))
    } else if matches!(
        mode,
        "run"
            | "baseline"
            | "run-negative"
            | "run-host"
            | "run-host-negative"
            | "run-imports"
            | "baseline-imports"
            | "run-imports-negative"
            | "run-host-imports"
            | "run-host-imports-negative"
            | "run-extensions"
            | "run-extensions-negative"
            | "run-native-lifecycle"
            | "run-native-lifecycle-negative"
            | "run-native-packages"
            | "run-native-packages-negative"
    ) {
        execute_experiment(mode, args)
    } else {
        Err("usage: glue-python-bootstrap-probe prepare-host-macos INSTALL_ONLY_ARCHIVE PREFIX OUTPUT | run-host-macos ARCHIVE | run-host-macos-negative ARCHIVE app-error | prepare-native-packages BASE NATIVE_DIRECTORY archived|host OUTPUT | run-native-packages ARCHIVE | run-native-packages-negative ARCHIVE app-error | corrupt-native-packages INPUT OUTPUT | prepare-native-lifecycle BASE NATIVE_DIRECTORY archived|host OUTPUT | run-native-lifecycle ARCHIVE | run-native-lifecycle-negative ARCHIVE app-error | corrupt-native-lifecycle INPUT OUTPUT | prepare-extensions BASE NATIVE_DIRECTORY archived|host OUTPUT | run-extensions ARCHIVE | run-extensions-negative ARCHIVE app-error | corrupt-extensions INPUT OUTPUT | prepare FULL BUNDLE OUTPUT | prepare-host FULL BUNDLE PREFIX OUTPUT | prepare-imports FULL BUNDLE OUTPUT | corrupt-imports INPUT OUTPUT | prepare-host-imports FULL PREFIX OUTPUT | corrupt-host-imports INPUT OUTPUT | run ARCHIVE | baseline ARCHIVE LIBRARY | run-negative ARCHIVE missing-encodings|bad-bytecode|app-error | run-host ARCHIVE | run-host-negative ARCHIVE app-error | run-imports ARCHIVE | baseline-imports ARCHIVE LIBRARY | run-imports-negative ARCHIVE app-error | run-host-imports ARCHIVE | run-host-imports-negative ARCHIVE app-error".into())
    }
}

#[cfg(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu",
    glue_python_boundary
))]
fn execute_experiment(mode: &str, args: &[std::ffi::OsString]) -> Result<(), String> {
    if matches!(mode, "run-native-packages" | "run-native-packages-negative") {
        let negative = mode == "run-native-packages-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong descriptor native package fixture arguments".into());
        }
        return linux::run_extensions(
            extension_profile::read_for(
                extension_profile::Profile::PackageImports,
                Path::new(&args[2]),
            )?,
            negative,
        );
    }
    if matches!(
        mode,
        "run-native-lifecycle" | "run-native-lifecycle-negative"
    ) {
        let negative = mode == "run-native-lifecycle-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong registered native lifecycle fixture arguments".into());
        }
        return linux::run_extensions(
            extension_profile::read_for(
                extension_profile::Profile::Lifecycle,
                Path::new(&args[2]),
            )?,
            negative,
        );
    }
    if matches!(mode, "run-extensions" | "run-extensions-negative") {
        let negative = mode == "run-extensions-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong registered native extension fixture arguments".into());
        }
        return linux::run_extensions(extension_profile::read(Path::new(&args[2]))?, negative);
    }
    if matches!(mode, "run-host-imports" | "run-host-imports-negative") {
        let negative = mode == "run-host-imports-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong host archive import fixture arguments".into());
        }
        return linux::run_host_imports(host_import_profile::read(Path::new(&args[2]))?, negative);
    }
    if matches!(
        mode,
        "run-imports" | "baseline-imports" | "run-imports-negative"
    ) {
        let expected = if mode == "run-imports" { 3 } else { 4 };
        if args.len() != expected || (mode == "run-imports-negative" && args[3] != "app-error") {
            return Err("wrong archive import fixture arguments".into());
        }
        return linux::run_imports(
            import_profile::read(Path::new(&args[2]))?,
            if mode == "baseline-imports" {
                Some(Path::new(&args[3]))
            } else {
                None
            },
            mode == "run-imports-negative",
        );
    }
    if matches!(mode, "run-host" | "run-host-negative") {
        let negative = mode == "run-host-negative";
        if args.len() != if negative { 4 } else { 3 } || (negative && args[3] != "app-error") {
            return Err("wrong host fixture arguments".into());
        }
        return linux::run_host(read_host_payload(Path::new(&args[2]))?, negative);
    }
    let expected = if mode == "run" { 3 } else { 4 };
    if args.len() != expected {
        return Err("wrong argument count".into());
    }
    let negative = if mode == "run-negative" {
        let kind = args[3].to_str().ok_or("invalid negative fixture kind")?;
        if !matches!(kind, "missing-encodings" | "bad-bytecode" | "app-error") {
            return Err("unknown negative fixture kind".into());
        }
        Some(kind)
    } else {
        None
    };
    let payload = read_payload(Path::new(&args[2]))?;
    linux::run(
        payload,
        if mode == "baseline" {
            Some(Path::new(&args[3]))
        } else {
            None
        },
        negative,
    )
}

#[cfg(not(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu",
    glue_python_boundary
)))]
fn execute_experiment(_: &str, _: &[std::ffi::OsString]) -> Result<(), String> {
    Err("execution requires pbs-bootstrap on GNU Linux arm64".into())
}

#[cfg(glue_python_macos_host)]
fn run_host_macos(payload: macos_host::Payload, negative: bool) -> Result<(), String> {
    macos::run_host(payload, negative)
}

#[cfg(not(glue_python_macos_host))]
fn run_host_macos(_: macos_host::Payload, _: bool) -> Result<(), String> {
    Err("execution requires pbs-bootstrap with a verified header tree on macOS arm64".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_profile() -> Manifest {
        profile_manifest(
            BTreeMap::from([(
                APP.into(),
                ResourceSpec {
                    size: HOST_APP.len() as u64,
                    sha256: digest(HOST_APP),
                    compression: Compression::Stored,
                },
            )]),
            Some(&host::Config::parse("/host Python").unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn explicit_host_profile_contains_only_the_shared_app() {
        let original = host_profile();
        let decoded = Manifest::from_json(&original.to_json().unwrap()).unwrap();
        assert_eq!(original, decoded);
        let config = admit_host_manifest(&decoded).unwrap();
        assert_eq!(config.library, "/host Python/lib/libpython3.13.so.1.0");
        assert_eq!(decoded.resources.keys().collect::<Vec<_>>(), vec![APP]);
        assert!(admit_manifest(&decoded).is_err());
    }

    #[test]
    fn host_profile_rejects_provider_identity_and_app_drift() {
        let original = host_profile();
        let mut changed = original.clone();
        changed.runtimes.get_mut("python").unwrap().abi = RuntimeAbi::Python {
            version: RuntimeVersion {
                major: 3,
                minor: 14,
                patch: 0,
            },
            gil: GilMode::Conventional,
            debug: false,
        };
        assert!(admit_host_manifest(&changed).is_err());
        changed = original.clone();
        changed.runtimes.get_mut("python").unwrap().build_id = "another-python-build".into();
        assert!(admit_host_manifest(&changed).is_err());
        changed = original.clone();
        changed.resources.get_mut(APP).unwrap().sha256 = digest(b"different app");
        assert!(admit_host_manifest(&changed).is_err());
        changed = original.clone();
        changed.resources.insert(
            LIBRARY.into(),
            ResourceSpec {
                size: LIBRARY_SIZE,
                sha256: LIBRARY_SHA.into(),
                compression: Compression::Stored,
            },
        );
        assert!(admit_host_manifest(&changed).is_err());
        changed = original;
        changed.runtimes.get_mut("python").unwrap().provisioning = Provisioning::Linked {
            provider: BundledProvider::PythonBuildStandalone,
            source: SourcePin {
                release: "20261009".into(),
                revision: None,
                artifact: "other".into(),
                sha256: digest(b"x"),
                variant: "other".into(),
            },
        };
        assert!(admit_host_manifest(&changed).is_err());
    }

    #[test]
    fn host_profile_rejects_mixed_installation_and_normalized_paths() {
        for (library, stdlib) in [
            (
                "/other/lib/libpython3.13.so.1.0",
                "/host Python/lib/python3.13",
            ),
            (
                "/host Python/lib/libpython3.13.so.1.0",
                "/host Python/../other/lib/python3.13",
            ),
            (
                "/host Python/lib/libpython3.13.so.1.0",
                "/host Python/lib/python3.14",
            ),
            (
                "/host Python/lib/libpython3.13.so.1.0",
                "relative/lib/python3.13",
            ),
        ] {
            let mut changed = host_profile();
            changed.runtimes.get_mut("python").unwrap().provisioning = Provisioning::Host {
                runtime_library: library.into(),
                stdlib: stdlib.into(),
                discovery: HostDiscovery::ExplicitPaths,
            };
            assert!(admit_host_manifest(&changed).is_err());
        }
    }
    #[test]
    fn profile_round_trip() {
        let specs = [LIBRARY, STDLIB, APP]
            .into_iter()
            .map(|key| {
                (
                    key.into(),
                    ResourceSpec {
                        size: 0,
                        sha256: digest(&[]),
                        compression: Compression::Stored,
                    },
                )
            })
            .collect();
        let m = manifest(specs).unwrap();
        assert_eq!(Manifest::from_json(&m.to_json().unwrap()).unwrap(), m);
    }
    #[test]
    fn incorrect_runtime_rejected() {
        assert!(check_library(b"not libpython").is_err());
    }
    #[test]
    fn missing_archive_rejected_portably() {
        assert!(read_payload(Path::new("/missing-bootstrap-fixture.glue")).is_err());
    }
    #[test]
    fn manifest_rejects_provider_target_and_runtime_drift() {
        let specs = [LIBRARY, STDLIB, APP]
            .into_iter()
            .map(|key| {
                (
                    key.into(),
                    ResourceSpec {
                        size: if key == LIBRARY { LIBRARY_SIZE } else { 1 },
                        sha256: if key == LIBRARY {
                            LIBRARY_SHA.into()
                        } else {
                            digest(b"x")
                        },
                        compression: Compression::Stored,
                    },
                )
            })
            .collect();
        let original = manifest(specs).unwrap();
        assert!(admit_manifest(&original).is_ok());
        let mut changed = original.clone();
        changed.runtimes.get_mut("python").unwrap().build_id = "other-stock-build".into();
        assert!(admit_manifest(&changed).is_err());
        changed = original.clone();
        changed.targets.get_mut("linux-arm64").unwrap().page_sizes = BTreeSet::from([16384]);
        assert!(admit_manifest(&changed).is_err());
        changed = original.clone();
        changed.resources.get_mut(LIBRARY).unwrap().sha256 = digest(b"other library");
        assert!(admit_manifest(&changed).is_err());
        changed = original;
        changed.resources.insert(
            "unexpected.py".into(),
            ResourceSpec {
                size: 1,
                sha256: digest(b"x"),
                compression: Compression::Stored,
            },
        );
        assert!(admit_manifest(&changed).is_err());
    }
}
