//! Controlled stock PBS bootstrap fixture, separate from product acquisition.
#![deny(unsafe_code)]

mod bundle;
mod host;
#[cfg(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu"
))]
#[allow(unsafe_code)]
mod linux;

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
        target_env = "gnu"
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
        target_env = "gnu"
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
        target_env = "gnu"
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
        target_env = "gnu"
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

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args.get(1).and_then(|s| s.to_str()).unwrap_or("");
    let result = if mode == "prepare" && args.len() == 5 {
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
    } else if matches!(
        mode,
        "run" | "baseline" | "run-negative" | "run-host" | "run-host-negative"
    ) {
        execute(mode, &args)
    } else {
        Err("usage: glue-python-bootstrap-probe prepare FULL BUNDLE OUTPUT | prepare-host FULL BUNDLE PREFIX OUTPUT | run ARCHIVE | baseline ARCHIVE LIBRARY | run-negative ARCHIVE missing-encodings|bad-bytecode|app-error | run-host ARCHIVE | run-host-negative ARCHIVE app-error".into())
    };
    if let Err(error) = result {
        eprintln!("glue-python-bootstrap-probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu"
))]
fn execute(mode: &str, args: &[std::ffi::OsString]) -> Result<(), String> {
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
    target_env = "gnu"
)))]
fn execute(_: &str, _: &[std::ffi::OsString]) -> Result<(), String> {
    // No archive open and no fallback on unsupported platforms/builds.
    eprintln!("glue-python-bootstrap-probe: execution requires pbs-bootstrap on GNU Linux arm64");
    std::process::exit(2)
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
