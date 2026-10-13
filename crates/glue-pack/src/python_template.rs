//! Portable preparation of the pinned Python runtime-template build inputs.
//!
//! Preparation reads explicit bounded inputs for the bundled provider and only
//! declares prerequisites for host providers. It never starts Python, discovers
//! a host installation or invokes an installer.

use super::{PackError, PackLimits, check_limit, io_error, resource_budget};
use glue_format::{ResourceSpec, digest};
use glue_runtime_python::packaging::{self, template};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

const FROZEN_BYTES: u64 = 139_523;

#[derive(Clone, Copy, Debug)]
pub enum TemplateInput<'a> {
    Bundled { full: &'a Path, frozen: &'a Path },
    HostFull { prefix: &'a str },
    HostInstall { prefix: &'a str },
}

/// Identities describe the actual published file bytes, including the JSON LF.
/// Paths are relative to the new template directory and are deterministic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TemplateFileIdentity {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TemplateReport {
    pub provider: String,
    pub provenance: template::TemplateProvenance,
    pub manifest: TemplateFileIdentity,
    pub provenance_file: TemplateFileIdentity,
    /// These resource paths live under the published `root/` directory.
    pub resources: BTreeMap<String, ResourceSpec>,
    pub resource_count: usize,
    pub uncompressed_bytes: u64,
}

/// Prepare a complete template in a new directory whose parent already exists.
///
/// Input and output-parent trees must remain stable throughout preparation.
/// Admission, identities and all input budgets finish before directory creation.
/// Existing outputs are never replaced or followed. Resources and provenance are
/// written first, then `manifest.json` is published last. A publication I/O error
/// can leave a partial newly created directory and always returns an error.
pub fn prepare(input: TemplateInput<'_>, output: &Path) -> Result<TemplateReport, PackError> {
    let owned = match input {
        TemplateInput::Bundled { full, frozen } => {
            let startup = read_frozen(frozen)?;
            let mut artifact = regular_file(full)?;
            template::bundled(&mut artifact, &startup)
        }
        TemplateInput::HostFull { prefix } => template::host(prefix, template::HostProvider::Full),
        TemplateInput::HostInstall { prefix } => {
            template::host(prefix, template::HostProvider::InstallOnly)
        }
    }
    .map_err(PackError::Profile)?;
    publish(owned, output)
}

fn publish(owned: template::RuntimeTemplate, output: &Path) -> Result<TemplateReport, PackError> {
    let archive_limits =
        packaging::validate_template(&owned.manifest).map_err(PackError::Profile)?;
    packaging::validate_application_contents(&owned.manifest, &owned.resources)
        .map_err(PackError::Profile)?;
    let limits = PackLimits {
        archive_limits,
        ..PackLimits::default()
    };
    let total = resource_budget(&owned.manifest, Path::new("<owned template>"), limits)?;
    let mut manifest_bytes = owned
        .manifest
        .to_json()
        .map_err(|source| PackError::Manifest {
            path: Path::new("<owned template>").to_owned(),
            source,
        })?;
    manifest_bytes.push(b'\n');
    check_limit(
        "manifest bytes",
        manifest_bytes.len() as u64,
        archive_limits.max_manifest_bytes,
    )?;
    let mut provenance_bytes = serde_json::to_vec(&owned.provenance)
        .map_err(|error| PackError::Profile(format!("serialize template provenance: {error}")))?;
    provenance_bytes.push(b'\n');
    let report = TemplateReport {
        provider: owned.provenance.provider.clone(),
        manifest: file_identity("manifest.json", &manifest_bytes),
        provenance_file: file_identity("provenance.json", &provenance_bytes),
        resources: owned.manifest.resources.clone(),
        resource_count: owned.resources.len(),
        uncompressed_bytes: total,
        provenance: owned.provenance,
    };

    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::metadata(parent).map_err(|source| io_error("stat template parent", parent, source))?;
    if !parent_metadata.is_dir() {
        return Err(io_error(
            "create template directory",
            output,
            std::io::Error::other("template parent is not a directory"),
        ));
    }
    fs::create_dir(output)
        .map_err(|source| io_error("create template directory", output, source))?;
    let root = output.join("root");
    fs::create_dir(&root).map_err(|source| io_error("create template root", &root, source))?;
    for (key, bytes) in &owned.resources {
        let destination = root.join(key);
        let parent = destination
            .parent()
            .expect("validated resource has a parent");
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create resource directory", parent, source))?;
        write_new(&destination, bytes)?;
    }
    write_new(&output.join("provenance.json"), &provenance_bytes)?;
    write_new(&output.join("manifest.json"), &manifest_bytes)?;
    Ok(report)
}

fn regular_file(path: &Path) -> Result<File, PackError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat template input", path, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io_error(
            "read template input",
            path,
            std::io::Error::other("template input must be a regular file and cannot be a symlink"),
        ));
    }
    let file = File::open(path).map_err(|source| io_error("open template input", path, source))?;
    if !file
        .metadata()
        .map_err(|source| io_error("stat open template input", path, source))?
        .is_file()
    {
        return Err(io_error(
            "read template input",
            path,
            std::io::Error::other("open template input is not a regular file"),
        ));
    }
    Ok(file)
}

fn read_frozen(path: &Path) -> Result<Vec<u8>, PackError> {
    let mut file = regular_file(path)?;
    let declared = file
        .metadata()
        .map_err(|source| io_error("stat frozen bootstrap", path, source))?
        .len();
    if declared != FROZEN_BYTES {
        return Err(PackError::Profile(format!(
            "frozen bootstrap must be exactly {FROZEN_BYTES} bytes, found {declared}"
        )));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(FROZEN_BYTES as usize)
        .map_err(|_| PackError::Allocation)?;
    Read::by_ref(&mut file)
        .take(FROZEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read frozen bootstrap", path, source))?;
    if bytes.len() as u64 != FROZEN_BYTES {
        return Err(PackError::Profile(
            "frozen bootstrap changed size while being read".into(),
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), PackError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create template file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write template file", path, source))?;
    file.flush()
        .map_err(|source| io_error("flush template file", path, source))
}

fn file_identity(path: &str, bytes: &[u8]) -> TemplateFileIdentity {
    TemplateFileIdentity {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glue_format::Manifest;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-python-template-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn host_input(prefix: &str, install: bool) -> TemplateInput<'_> {
        if install {
            TemplateInput::HostInstall { prefix }
        } else {
            TemplateInput::HostFull { prefix }
        }
    }

    #[test]
    fn host_templates_are_deterministic_without_installation_lookup() {
        let fixture = Fixture::new();
        let missing_prefix = fixture.path("missing target Python");
        let prefix = missing_prefix.to_str().unwrap();
        for install in [false, true] {
            let first = fixture.path(if install {
                "install-first"
            } else {
                "full-first"
            });
            let second = fixture.path(if install {
                "install-second"
            } else {
                "full-second"
            });
            let report = prepare(host_input(prefix, install), &first).unwrap();
            assert_eq!(
                report,
                prepare(host_input(prefix, install), &second).unwrap()
            );
            assert!(!missing_prefix.exists());

            let bytes = fs::read(first.join("manifest.json")).unwrap();
            assert_eq!(report.manifest, file_identity("manifest.json", &bytes));
            let manifest = Manifest::from_json(&bytes).unwrap();
            let mut canonical = manifest.to_json().unwrap();
            canonical.push(b'\n');
            assert_eq!(bytes, canonical);
            assert_eq!(bytes, fs::read(second.join("manifest.json")).unwrap());
            assert_eq!(manifest.resources, report.resources);
            assert_eq!(report.resource_count, manifest.resources.len());
            let mut total = 0;
            let mut resources = BTreeMap::new();
            for (key, spec) in &report.resources {
                let bytes = fs::read(first.join("root").join(key)).unwrap();
                assert_eq!(bytes.len() as u64, spec.size);
                assert_eq!(digest(&bytes), spec.sha256);
                assert_eq!(bytes, fs::read(second.join("root").join(key)).unwrap());
                total += spec.size;
                resources.insert(key.clone(), bytes);
            }
            assert_eq!(report.uncompressed_bytes, total);
            packaging::validate_application_contents(&manifest, &resources).unwrap();
            let provenance_bytes = fs::read(first.join("provenance.json")).unwrap();
            assert_eq!(
                report.provenance_file,
                file_identity("provenance.json", &provenance_bytes)
            );
            assert_eq!(provenance_bytes.last(), Some(&b'\n'));
            let provenance: serde_json::Value = serde_json::from_slice(&provenance_bytes).unwrap();
            assert_eq!(
                provenance,
                serde_json::to_value(&report.provenance).unwrap()
            );
            assert_eq!(provenance["provider"], report.provider);
            assert_eq!(provenance["host_prerequisites_verified"], false);
            assert_eq!(
                provenance["resources"],
                serde_json::to_value(&report.resources).unwrap()
            );
            assert_eq!(
                provenance["manifest_sha256"],
                digest(&manifest.to_json().unwrap())
            );
        }
    }

    #[test]
    fn invalid_host_declaration_is_rejected_before_output_lookup() {
        let fixture = Fixture::new();
        let output = fixture.path("missing-parent/output");
        for install in [false, true] {
            for prefix in ["relative", "/invalid/../prefix", "/invalid//prefix"] {
                assert!(matches!(
                    prepare(host_input(prefix, install), &output),
                    Err(PackError::Profile(_))
                ));
                assert!(!fixture.path("missing-parent").exists());
            }
        }
    }

    #[test]
    fn missing_or_non_directory_parent_is_not_materialized() {
        let fixture = Fixture::new();
        let missing = fixture.path("missing-parent/output");
        assert!(matches!(
            prepare(
                TemplateInput::HostFull {
                    prefix: "/missing target Python"
                },
                &missing
            ),
            Err(PackError::Io { .. })
        ));
        assert!(!fixture.path("missing-parent").exists());
        let file_parent = fixture.path("parent-file");
        fs::write(&file_parent, b"preserved parent").unwrap();
        assert!(matches!(
            prepare(
                TemplateInput::HostInstall {
                    prefix: "/missing target Python"
                },
                &file_parent.join("output")
            ),
            Err(PackError::Io { .. })
        ));
        assert_eq!(fs::read(file_parent).unwrap(), b"preserved parent");
    }

    #[test]
    fn existing_files_and_directories_are_preserved() {
        let fixture = Fixture::new();
        let output_file = fixture.path("existing-file");
        fs::write(&output_file, b"preserved output").unwrap();
        let output_directory = fixture.path("existing-directory");
        fs::create_dir(&output_directory).unwrap();
        fs::write(output_directory.join("sentinel"), b"preserved directory").unwrap();
        for install in [false, true] {
            for output in [&output_file, &output_directory] {
                assert!(matches!(
                    prepare(host_input("/missing target Python", install), output),
                    Err(PackError::Io { .. })
                ));
            }
            assert_eq!(fs::read(&output_file).unwrap(), b"preserved output");
            assert_eq!(
                fs::read(output_directory.join("sentinel")).unwrap(),
                b"preserved directory"
            );
            assert!(!output_directory.join("manifest.json").exists());
            assert!(!output_directory.join("root").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_symlinks_are_not_followed_or_replaced() {
        let fixture = Fixture::new();
        let target = fixture.path("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"preserved target").unwrap();
        let linked = fixture.path("linked-output");
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        let missing_target = fixture.path("missing-target");
        let dangling = fixture.path("dangling-output");
        std::os::unix::fs::symlink(&missing_target, &dangling).unwrap();
        for output in [&linked, &dangling] {
            assert!(matches!(
                prepare(
                    TemplateInput::HostFull {
                        prefix: "/missing target Python"
                    },
                    output
                ),
                Err(PackError::Io { .. })
            ));
            assert!(
                fs::symlink_metadata(output)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        assert_eq!(
            fs::read(target.join("sentinel")).unwrap(),
            b"preserved target"
        );
        assert!(!target.join("root").exists());
        assert!(!missing_target.exists());
    }

    #[test]
    fn invalid_owned_contents_are_rejected_before_directory_creation() {
        let fixture = Fixture::new();
        let mut owned =
            template::host("/missing target Python", template::HostProvider::Full).unwrap();
        owned.resources.get_mut("app/main.py").unwrap()[0] ^= 1;
        let output = fixture.path("output");
        assert!(matches!(
            publish(owned, &output),
            Err(PackError::Profile(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn frozen_input_is_bounded_and_requires_a_regular_file() {
        let fixture = Fixture::new();
        let full = fixture.path("bad-artifact");
        fs::write(&full, b"not a PBS artifact").unwrap();
        let frozen = fixture.path("frozen");
        let output = fixture.path("output");
        for length in [0, FROZEN_BYTES - 1, FROZEN_BYTES, FROZEN_BYTES + 1] {
            fs::write(&frozen, vec![0; length as usize]).unwrap();
            assert!(
                prepare(
                    TemplateInput::Bundled {
                        full: &full,
                        frozen: &frozen
                    },
                    &output
                )
                .is_err()
            );
            assert!(!output.exists());
        }
        assert!(
            prepare(
                TemplateInput::Bundled {
                    full: &full,
                    frozen: &fixture.0
                },
                &output
            )
            .is_err()
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn bundled_input_symlinks_are_rejected() {
        let fixture = Fixture::new();
        let frozen = fixture.path("frozen");
        fs::write(&frozen, vec![0; FROZEN_BYTES as usize]).unwrap();
        let full = fixture.path("artifact");
        fs::write(&full, b"not a PBS artifact").unwrap();
        let frozen_link = fixture.path("frozen-link");
        std::os::unix::fs::symlink(&frozen, &frozen_link).unwrap();
        let full_link = fixture.path("artifact-link");
        std::os::unix::fs::symlink(&full, &full_link).unwrap();
        let output = fixture.path("output");
        for (full, frozen) in [(&full, &frozen_link), (&full_link, &frozen)] {
            assert!(matches!(
                prepare(TemplateInput::Bundled { full, frozen }, &output),
                Err(PackError::Io { .. })
            ));
            assert!(!output.exists());
        }
    }
}
