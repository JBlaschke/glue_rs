//! Source applications paired with a pinned explicit-host source snapshot.
//!
//! Archive contents verify before host access. The installed startup paths stay
//! immutable/read-only; after startup, imports use verified owned source bytes.
#![cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]

use super::*;

pub(super) const BUILD_ID: &str = "pbs-20261009-cpython-3.13.16-pgo-lto-host-source-apps-v1";
pub(super) const PRELUDE: &[u8] =
    include_bytes!("../../../fixtures/python-host-source-apps/prelude.py");

pub(super) fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_archive_bytes: 16 * 1024 * 1024,
        max_manifest_bytes: 1024 * 1024,
        max_entry_bytes: source_app_profile::MAX_FILE_BYTES,
        max_total_uncompressed_bytes: 16 * 1024 * 1024,
        max_entries: 2048,
        max_central_directory_bytes: 256 * 1024,
        ..ArchiveLimits::default()
    }
}

pub(super) fn fixed_specs() -> BTreeMap<String, ResourceSpec> {
    BTreeMap::from([(
        import_profile::IMPORTER.into(),
        ResourceSpec {
            size: import_profile::BOOTSTRAP.len() as u64,
            sha256: digest(import_profile::BOOTSTRAP),
            compression: Compression::Deflate,
        },
    )])
}

pub(super) fn manifest_for(
    app_id: &str,
    component_id: &str,
    entry: &str,
    resources: BTreeMap<String, ResourceSpec>,
    config: &host::Config,
) -> Result<Manifest, String> {
    // The historical constructor requires app/main.py. Replace that temporary
    // shape before validating the new declared application entry.
    let mut manifest = profile_manifest(
        BTreeMap::from([(
            APP.into(),
            ResourceSpec {
                size: 0,
                sha256: digest(&[]),
                compression: Compression::Stored,
            },
        )]),
        Some(config),
    )?;
    manifest.resources = resources;
    manifest.app_id = app_id.into();
    manifest.entrypoint = component_id.into();
    manifest.components = BTreeMap::from([(
        component_id.into(),
        ComponentSpec {
            runtime: "python".into(),
            entry_point: entry.into(),
            native_modules: BTreeSet::new(),
        },
    )]);
    manifest.runtimes.get_mut("python").unwrap().build_id = BUILD_ID.into();
    manifest.validate().map_err(|error| error.to_string())?;
    Ok(manifest)
}

pub(super) fn admit(manifest: &Manifest) -> Result<host::Config, String> {
    source_app_profile::admit_application(manifest, &fixed_specs())?;
    let runtime = manifest
        .runtimes
        .get("python")
        .ok_or("host source app requires the pinned Python runtime identity")?;
    let Provisioning::Host {
        runtime_library,
        stdlib,
        discovery: HostDiscovery::ExplicitPaths,
    } = &runtime.provisioning
    else {
        return Err("source app requires the pinned explicit-host provider".into());
    };
    let prefix = stdlib
        .strip_suffix("/lib/python3.13")
        .ok_or("host source app stdlib differs from the fixed installation layout")?;
    let config = host::Config::parse(prefix)?;
    config.validate_source_snapshot_layout()?;
    let component = &manifest.components[&manifest.entrypoint];
    if runtime_library != &config.library
        || stdlib != &config.stdlib
        || *manifest
            != manifest_for(
                &manifest.app_id,
                &manifest.entrypoint,
                &component.entry_point,
                manifest.resources.clone(),
                &config,
            )?
    {
        return Err("manifest differs from the pinned host source app provider contract".into());
    }
    if manifest.to_json().map_err(|error| error.to_string())?.len() as u64
        > limits().max_manifest_bytes
    {
        return Err("host source app manifest exceeds 1 MiB".into());
    }
    Ok(config)
}

pub(super) struct Payload {
    pub config: host::Config,
    pub app_id: String,
    pub app: Vec<u8>,
    pub bootstrap: Vec<u8>,
    pub resources: BTreeMap<String, Vec<u8>>,
}

pub(super) fn read_archive(mut archive: Archive<File>) -> Result<Payload, String> {
    archive
        .check_limits(limits())
        .map_err(|error| error.to_string())?;
    let config = admit(archive.manifest())?;
    let app_id = archive.manifest().app_id.clone();
    let entry = archive.manifest().components[&archive.manifest().entrypoint]
        .entry_point
        .clone();
    let keys: Vec<_> = archive.manifest().resources.keys().cloned().collect();
    let mut resources = BTreeMap::new();
    for key in keys {
        resources.insert(
            key.clone(),
            archive
                .read_resource(&key)
                .map_err(|error| error.to_string())?,
        );
    }
    drop(archive);
    let mut bootstrap = PRELUDE.to_vec();
    bootstrap.extend(
        resources
            .remove(import_profile::IMPORTER)
            .ok_or("host source app pinned importer is missing")?,
    );
    Ok(Payload {
        config,
        app_id,
        app: source_entry::launcher(&entry)?,
        bootstrap,
        resources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Seek, SeekFrom, Write},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const ENTRY: &str = "app/tasks/report's [daily].py";

    fn spec(bytes: &[u8]) -> ResourceSpec {
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: digest(bytes),
            compression: Compression::Stored,
        }
    }

    fn contents() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (
                import_profile::IMPORTER.into(),
                import_profile::BOOTSTRAP.to_vec(),
            ),
            (ENTRY.into(), b"import customer\n".to_vec()),
            (
                "app/python/customer/__init__.py".into(),
                b"answer = 42\n".to_vec(),
            ),
            (
                "app/python/customer/assets/value.bin".into(),
                b"\0\xff".to_vec(),
            ),
        ])
    }

    fn fixture() -> Manifest {
        let mut resources = fixed_specs();
        for (key, bytes) in contents() {
            if key.starts_with("app/") {
                resources.insert(key, spec(&bytes));
            }
        }
        manifest_for(
            "customer.report",
            "launch-report",
            ENTRY,
            resources,
            &host::Config::parse("/missing host Python snapshot").unwrap(),
        )
        .unwrap()
    }

    fn reject(change: impl FnOnce(&mut Manifest)) {
        let mut manifest = fixture();
        change(&mut manifest);
        assert!(admit(&manifest).is_err());
    }

    #[test]
    fn host_source_app_admission_is_portable_and_keeps_provider_and_build_policy_explicit() {
        let manifest = fixture();
        let config = admit(&manifest).unwrap();
        assert_eq!(config.prefix, "/missing host Python snapshot");
        let decoded = Manifest::from_json(&manifest.to_json().unwrap()).unwrap();
        let selected = profile::validate(&decoded).unwrap();
        assert_eq!(selected.kind, profile::Kind::HostSourceApp);
        assert_eq!(
            selected.name(),
            "pinned explicit-host Python source application"
        );
        assert_eq!(profile::packaging_limits(&decoded).unwrap(), Some(limits()));
        assert_eq!(decoded.resources.len(), 4);
        assert!(
            decoded
                .resources
                .keys()
                .all(|key| key.starts_with("app/") || key == import_profile::IMPORTER)
        );
        assert!(limits().max_entry_bytes < LIBRARY_SIZE);
    }

    #[test]
    fn host_source_app_rejects_provider_library_layout_abi_and_target_drift() {
        reject(|manifest| {
            manifest.runtimes.get_mut("python").unwrap().build_id = "different".into()
        });
        reject(|manifest| {
            let Provisioning::Host {
                runtime_library, ..
            } = &mut manifest.runtimes.get_mut("python").unwrap().provisioning
            else {
                unreachable!()
            };
            runtime_library.push_str(".changed");
        });
        reject(|manifest| {
            let Provisioning::Host { stdlib, .. } =
                &mut manifest.runtimes.get_mut("python").unwrap().provisioning
            else {
                unreachable!()
            };
            stdlib.push_str(".changed");
        });
        reject(|manifest| {
            let RuntimeAbi::Python { debug, .. } =
                &mut manifest.runtimes.get_mut("python").unwrap().abi
            else {
                unreachable!()
            };
            *debug = true;
        });
        reject(|manifest| {
            manifest.targets.get_mut("linux-arm64").unwrap().arch = Architecture::X86_64
        });
        reject(|manifest| {
            let runtime = manifest.runtimes.remove("python").unwrap();
            manifest.runtimes.insert("renamed-python".into(), runtime);
            manifest
                .components
                .get_mut("launch-report")
                .unwrap()
                .runtime = "renamed-python".into();
        });
    }

    #[test]
    fn host_source_app_requires_exact_helper_and_excludes_archived_provider_bytes() {
        reject(|manifest| {
            manifest.resources.remove(import_profile::IMPORTER);
        });
        reject(|manifest| {
            manifest
                .resources
                .get_mut(import_profile::IMPORTER)
                .unwrap()
                .sha256 = digest(b"changed")
        });
        reject(|manifest| {
            manifest
                .resources
                .get_mut(import_profile::IMPORTER)
                .unwrap()
                .compression = Compression::Stored
        });
        for key in [LIBRARY, STDLIB, "stdlib/codecs.py", "unknown/value.txt"] {
            reject(|manifest| {
                manifest.resources.insert(key.into(), spec(b"extra"));
            });
        }
    }

    #[test]
    fn host_source_app_shares_source_layout_name_and_entry_restrictions() {
        for key in [
            "app/python/os.py",
            "app/python/sys.py",
            "app/python/encodings.py",
            "app/cache.PYC",
            "app/library.SO",
            "app/__pycache__/value.py",
            "app/python/customer.py",
        ] {
            reject(|manifest| {
                manifest.resources.insert(key.into(), spec(b"extra"));
            });
        }
        reject(|manifest| {
            manifest
                .components
                .get_mut("launch-report")
                .unwrap()
                .entry_point = "stdlib/codecs.py".into()
        });
        reject(|manifest| {
            manifest.resources.get_mut(ENTRY).unwrap().size =
                source_app_profile::MAX_ENTRY_BYTES + 1
        });
        reject(|manifest| {
            manifest
                .resources
                .get_mut("app/python/customer/assets/value.bin")
                .unwrap()
                .size = source_app_profile::MAX_FILE_BYTES + 1
        });
        reject(|manifest| manifest.app_id = "stock-pbs-archive-imports".into());
        reject(|manifest| manifest.app_id = "invalid app".into());
        let mut manifest = fixture();
        manifest.resources.insert(ENTRY.into(), spec(b""));
        admit(&manifest).unwrap();
    }

    struct ArchiveFixture(PathBuf);
    impl ArchiveFixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-host-source-app-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory)
        }
        fn archive(&self, manifest: &Manifest) -> Archive<File> {
            let path = self.0.join("source app.glue");
            write_archive(File::create(&path).unwrap(), manifest, &contents()).unwrap();
            Archive::open_with_limits(File::open(path).unwrap(), profile::archive_limits()).unwrap()
        }
    }
    impl Drop for ArchiveFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn host_source_archive_returns_verified_entry_bytes_before_any_host_acquisition() {
        let fixture = ArchiveFixture::new();
        let payload = read_archive(fixture.archive(&self::fixture())).unwrap();
        assert_eq!(payload.app_id, "customer.report");
        assert_eq!(payload.resources.len(), 3);
        assert_eq!(payload.resources[ENTRY], b"import customer\n");
        assert!(payload.app.is_ascii());
        assert!(payload.bootstrap.starts_with(PRELUDE));
        assert!(payload.bootstrap.ends_with(import_profile::BOOTSTRAP));
        // The selected host path does not exist; archive preparation did not
        // acquire it or discard the declared entry while building the launcher.
        assert!(!Path::new(&payload.config.prefix).exists());
    }

    #[test]
    fn corrupt_host_app_payload_rejects_before_snapshot_or_runtime_loading() {
        let fixture = ArchiveFixture::new();
        let archive = fixture.archive(&self::fixture());
        let zip_offset = 64 + archive.manifest().to_json().unwrap().len() as u64;
        let offset = zip_offset + archive.entries()[ENTRY].data_offset;
        drop(archive);
        let path = fixture.0.join("source app.glue");
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"X").unwrap();
        drop(file);
        let archive =
            Archive::open_with_limits(File::open(path).unwrap(), profile::archive_limits())
                .unwrap();
        let error = read_archive(archive).err().unwrap();
        assert!(error.contains("CRC"), "{error}");
    }

    #[test]
    fn host_source_application_tokens_remain_bound_to_the_opened_manifest() {
        let fixture = ArchiveFixture::new();
        let original = self::fixture();
        let selected = profile::validate(&original).unwrap();
        let mut changed = original;
        changed.app_id = "different.app".into();
        let error = execute(fixture.archive(&changed), selected).unwrap_err();
        assert_eq!(
            error.to_string(),
            "controlled Python profile belongs to another manifest"
        );
        assert!(!error.is_unsupported());
    }
}
