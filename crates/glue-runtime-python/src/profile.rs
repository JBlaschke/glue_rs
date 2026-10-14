//! Portable admission for pinned PBS Python source applications and fixtures.
//!
//! Admission does not acquire a provider or establish package compatibility.
//! Readiness is a separate build/platform check and never starts Python.

use super::{
    ExecutionError, extension_profile, host_import_profile, host_source_app_profile,
    import_profile, install_host_source_app_profile, metadata_profile, platform,
    source_app_profile,
};
use glue_format::{ArchiveLimits, Manifest, RuntimeAbi};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    BundledImports,
    HostImports,
    RegisteredExtensions,
    BundledSourceApp,
    HostSourceApp,
    InstallHostSourceApp,
    BundledMetadataApp,
    HostMetadataApp,
    InstallHostMetadataApp,
    StrippedInstallHostMetadataApp,
}

/// An admitted profile, tied to the manifest from which it was selected.
/// Its private fields prevent construction of an unchecked execution token.
#[derive(Clone, Debug)]
pub struct ControlledProfile {
    pub(crate) kind: Kind,
    pub(crate) manifest: Manifest,
}

impl ControlledProfile {
    /// A human-readable capability label; application identity remains in the
    /// manifest and no alternative provider is selected.
    pub fn name(&self) -> &'static str {
        match self.kind {
            Kind::BundledImports => "controlled bundled Python source/resources",
            Kind::HostImports => "controlled explicit-host Python source/resources",
            Kind::RegisteredExtensions => "controlled registered Python native extensions",
            Kind::BundledSourceApp => "pinned bundled Python source application",
            Kind::HostSourceApp => "pinned explicit-host Python source application",
            Kind::InstallHostSourceApp => "pinned install-only host Python source application",
            Kind::BundledMetadataApp => "pinned bundled Python distribution metadata application",
            Kind::HostMetadataApp => {
                "pinned explicit-host Python distribution metadata application"
            }
            Kind::InstallHostMetadataApp => {
                "pinned install-only host Python distribution metadata application"
            }
            Kind::StrippedInstallHostMetadataApp => {
                "pinned stripped install-only host Python distribution metadata application"
            }
        }
    }
}

/// Opening bounds for the controlled registry, including its pinned libpython
/// member larger than the generic archive reader's default 64 MiB limit.
/// Each selected profile applies its narrower bounds again before any read.
pub fn archive_limits() -> ArchiveLimits {
    import_profile::limits()
}

/// Validate pinned declarations on any platform, without opening host files.
pub fn validate(manifest: &Manifest) -> Result<ControlledProfile, ExecutionError> {
    manifest
        .validate()
        .map_err(|error| ExecutionError::failed(error.to_string()))?;
    let component = manifest
        .components
        .get(&manifest.entrypoint)
        .ok_or_else(|| ExecutionError::failed("selected Python component is missing"))?;
    let runtime = manifest
        .runtimes
        .get(&component.runtime)
        .ok_or_else(|| ExecutionError::failed("selected Python runtime is missing"))?;
    if !matches!(runtime.abi, RuntimeAbi::Python { .. }) {
        return Err(ExecutionError::unsupported(
            "selected runtime is not Python",
        ));
    }
    let kind = match manifest.app_id.as_str() {
        "stock-pbs-archive-imports" => {
            import_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::BundledImports
        }
        "stock-pbs-host-archive-imports" => {
            host_import_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::HostImports
        }
        extension_profile::APP_ID => {
            extension_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::RegisteredExtensions
        }
        _ if runtime.build_id == source_app_profile::BUILD_ID => {
            source_app_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::BundledSourceApp
        }
        _ if runtime.build_id == host_source_app_profile::BUILD_ID => {
            host_source_app_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::HostSourceApp
        }
        _ if runtime.build_id == install_host_source_app_profile::BUILD_ID => {
            install_host_source_app_profile::admit(manifest).map_err(ExecutionError::failed)?;
            Kind::InstallHostSourceApp
        }
        _ if runtime.build_id == metadata_profile::BUNDLED_BUILD_ID => {
            metadata_profile::admit_bundled(manifest).map_err(ExecutionError::failed)?;
            Kind::BundledMetadataApp
        }
        _ if runtime.build_id == metadata_profile::HOST_BUILD_ID => {
            metadata_profile::admit_host(manifest).map_err(ExecutionError::failed)?;
            Kind::HostMetadataApp
        }
        _ if runtime.build_id == metadata_profile::INSTALL_BUILD_ID => {
            metadata_profile::admit_install_host(manifest).map_err(ExecutionError::failed)?;
            Kind::InstallHostMetadataApp
        }
        _ if runtime.build_id == metadata_profile::STRIPPED_INSTALL_BUILD_ID => {
            metadata_profile::admit_stripped_install_host(manifest)
                .map_err(ExecutionError::failed)?;
            Kind::StrippedInstallHostMetadataApp
        }
        _ => {
            return Err(ExecutionError::unsupported(
                "Python execution requires a supported pinned PBS source-application or controlled fixture profile",
            ));
        }
    };
    Ok(ControlledProfile {
        kind,
        manifest: manifest.clone(),
    })
}

/// Return narrowly admitted build bounds for a pinned source application.
///
/// Other manifests retain the caller's ordinary packaging policy. Admission
/// uses the actual parsed manifest without reading runtime or app payloads.
pub fn packaging_limits(manifest: &Manifest) -> Result<Option<ArchiveLimits>, ExecutionError> {
    manifest
        .validate()
        .map_err(|error| ExecutionError::failed(error.to_string()))?;
    let component = &manifest.components[&manifest.entrypoint];
    let runtime = &manifest.runtimes[&component.runtime];
    if ![
        source_app_profile::BUILD_ID,
        host_source_app_profile::BUILD_ID,
        install_host_source_app_profile::BUILD_ID,
        metadata_profile::BUNDLED_BUILD_ID,
        metadata_profile::HOST_BUILD_ID,
        metadata_profile::INSTALL_BUILD_ID,
        metadata_profile::STRIPPED_INSTALL_BUILD_ID,
    ]
    .contains(&runtime.build_id.as_str())
    {
        return Ok(None);
    }
    let selected = validate(manifest)?;
    match selected.kind {
        Kind::BundledSourceApp => Ok(Some(source_app_profile::limits())),
        Kind::HostSourceApp => Ok(Some(host_source_app_profile::limits())),
        Kind::InstallHostSourceApp => Ok(Some(install_host_source_app_profile::limits())),
        Kind::BundledMetadataApp => Ok(Some(metadata_profile::limits_bundled())),
        Kind::HostMetadataApp
        | Kind::InstallHostMetadataApp
        | Kind::StrippedInstallHostMetadataApp => Ok(Some(metadata_profile::limits_host())),
        _ => Err(ExecutionError::failed(
            "source application build identity conflicts with a reserved fixture",
        )),
    }
}

/// Check feature and actual host compatibility for an already-admitted profile.
/// This observes the platform without loading or inspecting a host provider.
pub fn readiness(selected: &ControlledProfile) -> Result<(), ExecutionError> {
    platform::readiness(&selected.manifest).map_err(|error| match error {
        platform::ReadinessError::Unsupported(message) => ExecutionError::unsupported(message),
        platform::ReadinessError::Invalid(message) => ExecutionError::failed(message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{APP, digest, execute, host, profile_manifest};
    use glue_format::{Archive, Compression, ResourceSpec, write_archive};
    use std::{
        fs::{self, File, OpenOptions},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn host_manifest(prefix: &str) -> Manifest {
        let specs = import_profile::app_resources()
            .into_iter()
            .map(|(key, bytes)| {
                let compression = if key == import_profile::CORRUPT_SOURCE {
                    Compression::Stored
                } else {
                    Compression::Deflate
                };
                (
                    key,
                    ResourceSpec {
                        size: bytes.len() as u64,
                        sha256: digest(&bytes),
                        compression,
                    },
                )
            })
            .collect();
        let config = host::Config::parse(prefix).unwrap();
        let mut manifest = profile_manifest(specs, Some(&config)).unwrap();
        manifest.app_id = "stock-pbs-host-archive-imports".into();
        manifest.runtimes.get_mut("python").unwrap().build_id =
            "pbs-20261009-cpython-3.13.16-pgo-lto-host-archive-imports-v1".into();
        manifest
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "glue-python-profile-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn archive(&self, manifest: &Manifest) -> Archive<File> {
            let path = self.0.join("application.glue");
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            write_archive(file, manifest, &import_profile::app_resources()).unwrap();
            Archive::open_with_limits(File::open(path).unwrap(), archive_limits()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn declarations_are_portable_and_readiness_is_separate() {
        let manifest = host_manifest("/missing controlled Python");
        let selected = validate(&manifest).unwrap();
        assert_eq!(selected.kind, Kind::HostImports);
        assert_eq!(
            selected.name(),
            "controlled explicit-host Python source/resources"
        );
        assert!(archive_limits().max_entry_bytes >= crate::LIBRARY_SIZE);
        #[cfg(not(all(
            feature = "pbs-bootstrap",
            target_os = "linux",
            target_arch = "aarch64",
            target_env = "gnu",
            glue_python_boundary
        )))]
        assert!(readiness(&selected).unwrap_err().is_unsupported());
    }

    #[test]
    fn exact_profile_drift_is_invalid_and_unregistered_applications_are_unsupported() {
        let original = host_manifest("/missing controlled Python");
        let mut changed = original.clone();
        changed.resources.get_mut(APP).unwrap().sha256 = digest(b"changed app");
        assert!(!validate(&changed).unwrap_err().is_unsupported());
        let mut changed = original.clone();
        changed.runtimes.get_mut("python").unwrap().build_id = "unreviewed build".into();
        assert!(!validate(&changed).unwrap_err().is_unsupported());
        let mut changed = original;
        changed.app_id = "arbitrary-python-app".into();
        assert!(validate(&changed).unwrap_err().is_unsupported());
    }

    #[test]
    fn execution_tokens_cannot_be_reused_for_a_different_manifest() {
        let selected = validate(&host_manifest("/first controlled Python")).unwrap();
        let fixture = Fixture::new();
        let archive = fixture.archive(&host_manifest("/second controlled Python"));
        let error = execute(archive, selected).unwrap_err();
        assert!(!error.is_unsupported());
        assert!(error.to_string().contains("another manifest"));
    }

    #[test]
    fn archive_preparation_uses_the_open_descriptor_after_its_path_is_removed() {
        let manifest = host_manifest("/missing controlled Python");
        let fixture = Fixture::new();
        let archive = fixture.archive(&manifest);
        fs::remove_file(fixture.0.join("application.glue")).unwrap();
        let payload = host_import_profile::read_archive(archive).unwrap();
        assert_eq!(payload.app, import_profile::app_resources()[APP]);
        assert_eq!(payload.config.prefix, "/missing controlled Python");
    }

    #[test]
    #[cfg(not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )))]
    fn unavailable_executor_does_not_acquire_an_explicit_missing_host() {
        let manifest = host_manifest("/missing controlled Python");
        let fixture = Fixture::new();
        let archive = fixture.archive(&manifest);
        let selected = validate(&manifest).unwrap();
        let error = execute(archive, selected).unwrap_err();
        assert!(error.is_unsupported());
    }
}
