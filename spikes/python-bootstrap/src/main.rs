//! Controlled stock PBS bootstrap fixture, separate from product acquisition.
#![deny(unsafe_code)]

mod bundle;
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
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let result = Manifest {
        schema_version: 0,
        app_id: "stock-pbs-bootstrap".into(),
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
                build_id: "pbs-20261009-cpython-3.13.16-pgo-lto-frozen-bootstrap-v1".into(),
                abi: RuntimeAbi::Python {
                    version: RuntimeVersion {
                        major: 3,
                        minor: 13,
                        patch: 16,
                    },
                    gil: GilMode::Conventional,
                    debug: false,
                },
                provisioning: Provisioning::Bundled {
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
                },
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
    } else if matches!(mode, "run" | "baseline" | "run-negative") {
        execute(mode, &args)
    } else {
        Err("usage: glue-python-bootstrap-probe prepare FULL BUNDLE OUTPUT | run ARCHIVE | baseline ARCHIVE LIBRARY | run-negative ARCHIVE missing-encodings|bad-bytecode|app-error".into())
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
