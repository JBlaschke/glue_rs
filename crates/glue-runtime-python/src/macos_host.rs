//! Explicit installed macOS arm64 host layout for the pinned stock PBS
//! CPython 3.13.16 startup fixture.
//!
//! Preparation verifies the independently pinned install-only artifact and
//! selects its library and the six reviewed startup sources without extracting
//! anything. Execution verifies the same identities in the declared
//! installation before dyld loads the library by its verified path. This is a
//! startup subset on one observed macOS cell; it is not host discovery, a
//! complete stdlib policy, a bundled macOS provider or a native-extension profile.
#![cfg_attr(not(glue_python_macos_host), allow(dead_code))]

use super::{APP, HOST_APP, bundle::MODULE_SPECS, digest, host, host_limits};
use glue_format::{
    Architecture, Archive, ComponentSpec, Compression, GilMode, HostDiscovery, Manifest,
    OperatingSystem, Provisioning, ResourceSpec, RuntimeAbi, RuntimeSpec, RuntimeVersion,
    TargetAbi, TargetProfile, write_archive,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    path::Path,
};

pub(super) const APP_ID: &str = "stock-pbs-host-startup-macos";
pub(super) const TARGET: &str = "macos-arm64";
pub(super) const BUILD_ID: &str = "pbs-20261009-cpython-3.13.16-macos-host-startup-v1";
/// Observed test cell, not an inferred upstream compatibility floor.
pub(super) const OBSERVED_OS_VERSION: &str = "26.7";
pub(super) const PAGE_SIZE: u32 = 16384;
const LIBRARY_SUFFIX: &str = "/lib/libpython3.13.dylib";
const STDLIB_SUFFIX: &str = "/lib/python3.13";
const LIBRARY_MEMBER: &str = "python/lib/libpython3.13.dylib";
const SOURCE_MEMBER_PREFIX: &str = "python/lib/python3.13/";
const PINNED_SOURCE_PREFIX: &str = "install/lib/python3.13/";
const MAX_LIBRARY_BYTES: u64 = 64 * 1024 * 1024;
const SELECTED_LIMIT: u64 = 32 * 1024 * 1024;
const PINS: &[u8] = include_bytes!("../../../fixtures/python-host-macos/pins.json");

/// Build-time identity of the pinned macOS arm64 install-only artifact and
/// its shared library. This is not a runtime manifest.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pins {
    pub schema_version: u32,
    pub release: String,
    pub python_version: String,
    pub target_triple: String,
    pub install_only: glue_pbs::pins::ArtifactPin,
    pub library: LibraryPin,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LibraryPin {
    pub member: String,
    pub size: u64,
    pub sha256: String,
}

impl Pins {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 16 * 1024 {
            return Err("macOS PBS pins exceed 16 KiB".into());
        }
        let pins: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid macOS PBS pins: {error}"))?;
        pins.validate()?;
        Ok(pins)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 0
            || self.target_triple != "aarch64-apple-darwin"
            || self.python_version != "3.13.16"
            || self.release != "20261009"
        {
            return Err(
                "macOS PBS pins require schema 0, aarch64-apple-darwin, CPython 3.13.16 and release 20261009".into(),
            );
        }
        let filename = format!(
            "cpython-{}+{}-{}-install_only.tar.gz",
            self.python_version, self.release, self.target_triple
        );
        let url = format!(
            "https://github.com/astral-sh/python-build-standalone/releases/download/{}/{}",
            self.release,
            filename.replace('+', "%2B")
        );
        let pin = &self.install_only;
        if pin.filename != filename
            || pin.url != url
            || !hex(&pin.sha256)
            || pin.size == 0
            || pin.size > glue_pbs::pins::MAX_COMPRESSED_BYTES
        {
            return Err("macOS PBS artifact identity, size, URL or SHA-256 is invalid".into());
        }
        if self.library.member != LIBRARY_MEMBER
            || self.library.size == 0
            || self.library.size > MAX_LIBRARY_BYTES
            || !hex(&self.library.sha256)
        {
            return Err("macOS PBS library pin is invalid".into());
        }
        Ok(())
    }
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Config {
    pub prefix: String,
    pub library: String,
    pub stdlib: String,
}

/// Retain the verified descriptors through interpreter finalization. dyld
/// loads the library by its verified canonical path; the retained descriptor
/// and the loaded image's identity are compared again after loading.
#[derive(Debug)]
pub(super) struct Verified {
    pub config: Config,
    pub library: File,
    _sources: Vec<File>,
    _directories: Vec<File>,
}

impl Config {
    pub(super) fn parse(prefix: &str) -> Result<Self, String> {
        host::validate_path(prefix)?;
        if prefix == "/" {
            return Err("host prefix must name an installation directory".into());
        }
        let library = format!("{prefix}{LIBRARY_SUFFIX}");
        let stdlib = format!("{prefix}{STDLIB_SUFFIX}");
        host::validate_path(&library)?;
        host::validate_path(&stdlib)?;
        Ok(Self {
            prefix: prefix.into(),
            library,
            stdlib,
        })
    }

    /// Require the exact pinned library and six reviewed startup sources,
    /// without following symlinks or admitting startup bytecode caches.
    #[cfg(unix)]
    pub(super) fn verify(&self) -> Result<Verified, String> {
        if Self::parse(&self.prefix)? != *self {
            return Err("host configuration differs from the fixed installation layout".into());
        }
        let pins = Pins::parse(PINS)?;
        let mut directories = host::open_directories(Path::new(&self.stdlib))?;
        let encodings = Path::new(&self.stdlib).join("encodings");
        directories.append(&mut host::open_directories(&encodings)?);
        host::require_cache_absent(&Path::new(&self.stdlib).join("__pycache__"))?;
        host::require_cache_absent(&encodings.join("__pycache__"))?;
        let (library, mut library_dirs) = host::verified_file(
            Path::new(&self.library),
            pins.library.size,
            &pins.library.sha256,
        )?;
        directories.append(&mut library_dirs);
        let mut sources = Vec::with_capacity(MODULE_SPECS.len());
        for spec in &MODULE_SPECS {
            let relative = pinned_relative(spec.source_path)?;
            let source = format!("{}/{relative}", self.stdlib);
            host::validate_path(&source)?;
            let (file, mut source_dirs) =
                host::verified_file(Path::new(&source), spec.source_size, spec.source_sha256)?;
            sources.push(file);
            directories.append(&mut source_dirs);
        }
        Ok(Verified {
            config: self.clone(),
            library,
            _sources: sources,
            _directories: directories,
        })
    }
}

fn pinned_relative(source_path: &str) -> Result<&str, String> {
    source_path
        .strip_prefix(PINNED_SOURCE_PREFIX)
        .ok_or_else(|| "reviewed startup source is outside the fixed standard library".into())
}

fn source_member(source_path: &str) -> Result<String, String> {
    Ok(format!(
        "{SOURCE_MEMBER_PREFIX}{}",
        pinned_relative(source_path)?
    ))
}

fn app_specs() -> BTreeMap<String, ResourceSpec> {
    BTreeMap::from([(
        APP.into(),
        ResourceSpec {
            size: HOST_APP.len() as u64,
            sha256: digest(HOST_APP),
            compression: Compression::Stored,
        },
    )])
}

/// The exact manifest of the macOS explicit-host startup fixture. The target
/// records the observed cell; it is not a tested compatibility floor.
pub(super) fn profile_manifest(config: &Config) -> Result<Manifest, String> {
    let result = Manifest {
        schema_version: 0,
        app_id: APP_ID.into(),
        entrypoint: "main".into(),
        targets: BTreeMap::from([(
            TARGET.into(),
            TargetProfile {
                os: OperatingSystem::Macos,
                arch: Architecture::Aarch64,
                minimum_os_version: OBSERVED_OS_VERSION.into(),
                abi: TargetAbi::Darwin,
                page_sizes: BTreeSet::from([PAGE_SIZE]),
                cpu_features: BTreeSet::new(),
            },
        )]),
        resources: app_specs(),
        runtimes: BTreeMap::from([(
            "python".into(),
            RuntimeSpec {
                target: TARGET.into(),
                build_id: BUILD_ID.into(),
                abi: RuntimeAbi::Python {
                    version: RuntimeVersion {
                        major: 3,
                        minor: 13,
                        patch: 16,
                    },
                    gil: GilMode::Conventional,
                    debug: false,
                },
                provisioning: Provisioning::Host {
                    runtime_library: config.library.clone(),
                    stdlib: config.stdlib.clone(),
                    discovery: HostDiscovery::ExplicitPaths,
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

pub(super) fn admit_manifest(actual: &Manifest) -> Result<Config, String> {
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
        return Err("archive differs from the explicit macOS host Python fixture profile".into());
    };
    let prefix = stdlib
        .strip_suffix(STDLIB_SUFFIX)
        .ok_or("host stdlib does not use the fixed installation layout")?;
    let config = Config::parse(prefix)?;
    if *runtime_library != config.library || *stdlib != config.stdlib {
        return Err("host library and stdlib installation paths disagree".into());
    }
    if *actual != profile_manifest(&config)? {
        return Err("archive differs from the explicit macOS host Python fixture profile".into());
    }
    Ok(config)
}

pub(super) struct Payload {
    pub config: Config,
    pub app: Vec<u8>,
}

pub(super) fn read_payload(path: &Path) -> Result<Payload, String> {
    let mut archive =
        Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, host_limits())
            .map_err(|e| e.to_string())?;
    let config = admit_manifest(archive.manifest())?;
    if archive
        .entries()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from([APP])
    {
        return Err("macOS host fixture contains unexpected archive payloads".into());
    }
    let app = archive.read_resource(APP).map_err(|e| e.to_string())?;
    if app != HOST_APP {
        return Err("host startup app differs from the shared compiled fixture".into());
    }
    Ok(Payload { config, app })
}

/// Verify the pinned install-only artifact's identity, library and reviewed
/// startup sources without extraction, then write the application-only archive.
/// The declared installation prefix need not exist on the preparing computer.
pub(super) fn prepare(install_only: &Path, prefix: &str, output: &Path) -> Result<(), String> {
    let pins = Pins::parse(PINS)?;
    let config = Config::parse(prefix)?;
    let mut selection = BTreeSet::from([LIBRARY_MEMBER.to_string()]);
    for spec in &MODULE_SPECS {
        selection.insert(source_member(spec.source_path)?);
    }
    let mut input = File::open(install_only).map_err(|e| e.to_string())?;
    let mut selected = glue_pbs::inspect_install_pin_selected(
        &pins.install_only,
        &mut input,
        &selection,
        SELECTED_LIMIT,
    )?;
    let library = selected
        .files
        .remove(LIBRARY_MEMBER)
        .ok_or("missing selected macOS runtime library")?;
    if library.len() as u64 != pins.library.size || digest(&library) != pins.library.sha256 {
        return Err("stock PBS macOS runtime library identity mismatch".into());
    }
    for spec in &MODULE_SPECS {
        let bytes = selected
            .files
            .remove(&source_member(spec.source_path)?)
            .ok_or("missing selected startup source")?;
        if bytes.len() as u64 != spec.source_size || digest(&bytes) != spec.source_sha256 {
            return Err(format!(
                "reviewed startup source {} differs in the macOS artifact",
                spec.name
            ));
        }
    }
    let resources = BTreeMap::from([(APP.to_string(), HOST_APP.to_vec())]);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &profile_manifest(&config)?, &resources).map_err(|e| e.to_string())?;
    println!("prepared explicit macOS host Python startup archive");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_pins_describe_the_exact_macos_artifact_and_library() {
        let pins = Pins::parse(PINS).unwrap();
        assert_eq!(pins.install_only.size, 25_378_093);
        assert_eq!(pins.library.size, 18_023_664);
        assert_eq!(pins.library.member, LIBRARY_MEMBER);
        for (field, value) in [
            ("target_triple", "aarch64-unknown-linux-gnu"),
            ("release", "20261003"),
            ("python_version", "3.13.15"),
        ] {
            let text = String::from_utf8(PINS.to_vec()).unwrap();
            let original = match field {
                "target_triple" => "aarch64-apple-darwin",
                "release" => "20261009",
                _ => "3.13.16",
            };
            let changed = text.replacen(
                &format!("\"{field}\": \"{original}\""),
                &format!("\"{field}\": \"{value}\""),
                1,
            );
            assert_ne!(changed, text);
            assert!(Pins::parse(changed.as_bytes()).is_err(), "{field}");
        }
        let text = String::from_utf8(PINS.to_vec()).unwrap();
        let extra = text.replacen(
            "\"schema_version\": 0,",
            "\"schema_version\": 0, \"extra\": 1,",
            1,
        );
        assert!(Pins::parse(extra.as_bytes()).is_err());
    }

    #[test]
    fn config_uses_the_fixed_dylib_layout_and_rejects_invalid_prefixes() {
        let config = Config::parse("/opt/pinned python").unwrap();
        assert_eq!(config.library, "/opt/pinned python/lib/libpython3.13.dylib");
        assert_eq!(config.stdlib, "/opt/pinned python/lib/python3.13");
        for prefix in [
            "/",
            "",
            "relative",
            "/trailing/",
            "/a//b",
            "/a/../b",
            "/non\u{e9}",
        ] {
            assert!(Config::parse(prefix).is_err(), "{prefix:?}");
        }
    }

    #[test]
    fn manifest_round_trips_through_admission_and_rejects_other_profiles() {
        let config = Config::parse("/pinned macOS Python").unwrap();
        let manifest = profile_manifest(&config).unwrap();
        assert_eq!(manifest.app_id, APP_ID);
        assert_eq!(admit_manifest(&manifest).unwrap(), config);
        let decoded = Manifest::from_json(&manifest.to_json().unwrap()).unwrap();
        assert_eq!(admit_manifest(&decoded).unwrap(), config);

        let mut other = manifest.clone();
        other.app_id = "stock-pbs-host-startup".into();
        assert!(admit_manifest(&other).is_err());
        let mut other = manifest.clone();
        other.resources.get_mut(APP).unwrap().sha256 = digest(b"changed app");
        assert!(admit_manifest(&other).is_err());
        let mut other = manifest.clone();
        other.runtimes.get_mut("python").unwrap().build_id = "unreviewed".into();
        assert!(admit_manifest(&other).is_err());
        let mut other = manifest;
        other
            .targets
            .get_mut(TARGET)
            .unwrap()
            .page_sizes
            .insert(4096);
        assert!(admit_manifest(&other).is_err());

        let linux = crate::profile_manifest(
            app_specs(),
            Some(&host::Config::parse("/pinned Linux Python").unwrap()),
        )
        .unwrap();
        assert!(admit_manifest(&linux).is_err());
        assert!(crate::admit_host_manifest(&profile_manifest(&config).unwrap()).is_err());
    }

    #[test]
    fn payload_reads_only_the_shared_application() {
        let config = Config::parse("/pinned macOS Python").unwrap();
        let directory = std::env::temp_dir().join(format!(
            "glue-macos-host-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("host.glue");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        write_archive(
            file,
            &profile_manifest(&config).unwrap(),
            &BTreeMap::from([(APP.to_string(), HOST_APP.to_vec())]),
        )
        .unwrap();
        let payload = read_payload(&path).unwrap();
        assert_eq!(payload.config, config);
        assert_eq!(payload.app, HOST_APP);
        assert!(read_payload(&directory.join("missing.glue")).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn startup_members_map_to_the_install_only_layout() {
        for spec in &MODULE_SPECS {
            let member = source_member(spec.source_path).unwrap();
            assert!(member.starts_with("python/lib/python3.13/"), "{member}");
            assert!(!member.contains("install/"));
        }
        assert!(source_member("lib/python3.13/codecs.py").is_err());
    }
}
