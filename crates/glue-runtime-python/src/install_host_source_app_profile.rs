//! Exact install-only host source applications with pinned startup caches.
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

pub(super) const BUILD_ID: &str =
    "pbs-20261009-cpython-3.13.16-pgo-lto-host-install-source-apps-v1";

pub(super) fn limits() -> ArchiveLimits {
    host_source_app_profile::limits()
}

#[cfg(test)]
pub(super) fn manifest_for(
    app_id: &str,
    component_id: &str,
    entry: &str,
    resources: BTreeMap<String, ResourceSpec>,
    config: &host::Config,
) -> Result<Manifest, String> {
    host_source_app_profile::manifest_for_build(
        app_id,
        component_id,
        entry,
        resources,
        config,
        BUILD_ID,
    )
}

pub(super) fn admit(manifest: &Manifest) -> Result<host::Config, String> {
    host_source_app_profile::admit_for_build(
        manifest,
        BUILD_ID,
        host::Config::validate_install_source_snapshot_layout,
    )
}

pub(super) fn read_archive(
    archive: Archive<File>,
) -> Result<host_source_app_profile::Payload, String> {
    host_source_app_profile::read_archive_with(archive, admit)
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

    const ENTRY: &str = "app/task's [report].py";

    fn contents() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (
                import_profile::IMPORTER.into(),
                import_profile::BOOTSTRAP.to_vec(),
            ),
            (ENTRY.into(), b"import customer\n".to_vec()),
            ("app/python/customer.py".into(), b"answer = 42\n".to_vec()),
        ])
    }

    fn manifest() -> Manifest {
        let mut resources = host_source_app_profile::fixed_specs();
        resources.extend(
            contents()
                .into_iter()
                .filter(|(key, _)| key.starts_with("app/"))
                .map(|(key, bytes)| {
                    (
                        key,
                        ResourceSpec {
                            size: bytes.len() as u64,
                            sha256: digest(&bytes),
                            compression: Compression::Stored,
                        },
                    )
                }),
        );
        manifest_for(
            "customer.report",
            "report",
            ENTRY,
            resources,
            &host::Config::parse("/missing installed Python").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn install_only_admission_is_portable_and_distinct_from_full_host() {
        let manifest = manifest();
        let config = admit(&manifest).unwrap();
        assert_eq!(config.prefix, "/missing installed Python");
        let selected = profile::validate(&manifest).unwrap();
        assert_eq!(selected.kind, profile::Kind::InstallHostSourceApp);
        assert_eq!(
            selected.name(),
            "pinned install-only host Python source application"
        );
        assert_eq!(
            profile::packaging_limits(&manifest).unwrap(),
            Some(limits())
        );
        assert!(host_source_app_profile::admit(&manifest).is_err());
        let mut full = manifest;
        full.runtimes.get_mut("python").unwrap().build_id =
            host_source_app_profile::BUILD_ID.into();
        assert!(admit(&full).is_err());
        assert_eq!(
            profile::validate(&full).unwrap().kind,
            profile::Kind::HostSourceApp
        );
    }

    #[test]
    fn install_only_keeps_runtime_names_reserved_and_payloads_source_only() {
        for key in [
            "app/python/test.py",
            "app/python/os.py",
            "app/cache.PYC",
            LIBRARY,
            "stdlib/codecs.py",
        ] {
            let mut manifest = manifest();
            manifest.resources.insert(
                key.into(),
                ResourceSpec {
                    size: 0,
                    sha256: digest(&[]),
                    compression: Compression::Stored,
                },
            );
            assert!(admit(&manifest).is_err(), "{key}");
        }
        let mut helper = manifest();
        helper
            .resources
            .get_mut(import_profile::IMPORTER)
            .unwrap()
            .sha256 = digest(b"different");
        assert!(admit(&helper).is_err());
    }

    #[test]
    fn install_only_rejects_provider_runtime_key_abi_and_target_drift() {
        for mode in 0..5 {
            let mut manifest = manifest();
            match mode {
                0 => {
                    let Provisioning::Host {
                        runtime_library, ..
                    } = &mut manifest.runtimes.get_mut("python").unwrap().provisioning
                    else {
                        unreachable!()
                    };
                    runtime_library.push_str(".changed");
                }
                1 => {
                    let RuntimeAbi::Python { debug, .. } =
                        &mut manifest.runtimes.get_mut("python").unwrap().abi
                    else {
                        unreachable!()
                    };
                    *debug = true;
                }
                2 => manifest.targets.get_mut("linux-arm64").unwrap().arch = Architecture::X86_64,
                3 => {
                    let runtime = manifest.runtimes.remove("python").unwrap();
                    manifest.runtimes.insert("renamed".into(), runtime);
                    manifest.components.get_mut("report").unwrap().runtime = "renamed".into();
                }
                _ => manifest.app_id = "stock-pbs-host-archive-imports".into(),
            }
            assert!(admit(&manifest).is_err(), "{mode}");
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "glue-install-host-app-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn archive(&self, manifest: &Manifest) -> Archive<File> {
            let path = self.0.join("application.glue");
            write_archive(File::create(path).unwrap(), manifest, &contents()).unwrap();
            self.open()
        }
        fn open(&self) -> Archive<File> {
            Archive::open_with_limits(
                File::open(self.0.join("application.glue")).unwrap(),
                profile::archive_limits(),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn install_only_prepares_verified_owned_entry_before_installed_host_access() {
        let fixture = Fixture::new();
        let payload = read_archive(fixture.archive(&manifest())).unwrap();
        assert_eq!(payload.resources[ENTRY], b"import customer\n");
        assert!(
            payload
                .bootstrap
                .starts_with(host_source_app_profile::PRELUDE)
        );
        assert!(payload.bootstrap.ends_with(import_profile::BOOTSTRAP));
        assert!(!Path::new(&payload.config.prefix).exists());
    }

    #[test]
    fn install_only_crc_failure_precedes_cache_or_library_acquisition() {
        let fixture = Fixture::new();
        let archive = fixture.archive(&manifest());
        let offset = 64
            + archive.manifest().to_json().unwrap().len() as u64
            + archive.entries()[ENTRY].data_offset;
        drop(archive);
        let mut file = OpenOptions::new()
            .write(true)
            .open(fixture.0.join("application.glue"))
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"X").unwrap();
        drop(file);
        assert!(read_archive(fixture.open()).err().unwrap().contains("CRC"));
    }

    #[test]
    fn install_only_profile_token_is_bound_to_the_actual_opened_manifest() {
        let fixture = Fixture::new();
        let original = manifest();
        let token = profile::validate(&original).unwrap();
        let mut different = original;
        different.app_id = "different.report".into();
        assert_eq!(
            execute(fixture.archive(&different), token)
                .unwrap_err()
                .to_string(),
            "controlled Python profile belongs to another manifest"
        );
    }
}
