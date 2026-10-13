//! Build-time packaging of an explicit manifest inventory.
//!
//! This module performs ordinary filesystem reads on the builder. It never
//! discovers, installs, downloads or executes missing dependencies, and it is
//! separate from the runtime's read-only archive reader.

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
pub mod python_template;

use glue_format::{
    Archive, ArchiveError, ArchiveLimits, FormatError, MAX_MANIFEST_BYTES, Manifest, ResourcePath,
    digest, write_archive,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackLimits {
    /// Maximum sum of declared, uncompressed build inputs held in memory.
    pub max_input_bytes: u64,
    pub archive_limits: ArchiveLimits,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024 * 1024,
            archive_limits: ArchiveLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BuildReport {
    pub archive_bytes: u64,
    pub resource_count: usize,
    pub uncompressed_bytes: u64,
    /// Identity of the canonical manifest embedded in the generated container.
    pub manifest_sha256: String,
    pub archive_sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("{action} {path:?}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("manifest {path:?}: {source}")]
    Manifest {
        path: PathBuf,
        #[source]
        source: FormatError,
    },
    #[error("packaging profile: {0}")]
    Profile(String),
    #[error("invalid input root {path:?}: {reason}")]
    Root { path: PathBuf, reason: &'static str },
    #[error("resource {resource:?} at {path:?}: {reason}")]
    Resource {
        resource: String,
        path: PathBuf,
        reason: String,
    },
    #[error("build exceeds {limit}: {actual} > {maximum}")]
    Limit {
        limit: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("unable to allocate a bounded build input buffer")]
    Allocation,
    #[error("generated archive: {0}")]
    Archive(#[from] ArchiveError),
}

/// Build exactly the files declared by `manifest_path`, under `root`.
///
/// Resource components must be directories followed by a regular file; symlinks
/// are rejected. The build input tree must remain stable while it is read. All
/// declarations, bytes and generated-archive checks finish before `output` is
/// opened with `create_new`, preserving existing files and symlinks. An output
/// write failure can leave a partial file and always returns an error.
pub fn build(manifest_path: &Path, root: &Path, output: &Path) -> Result<BuildReport, PackError> {
    build_with_limits(manifest_path, root, output, PackLimits::default())
}

pub fn build_with_limits(
    manifest_path: &Path,
    root: &Path,
    output: &Path,
    limits: PackLimits,
) -> Result<BuildReport, PackError> {
    let manifest_bytes = read_manifest(manifest_path, limits.archive_limits.max_manifest_bytes)?;
    build_admitted(manifest_path, root, output, manifest_bytes, |_| Ok(limits))
}

/// Select a packaging policy from the same manifest that will be packaged.
///
/// The schema's 16 MiB manifest bound applies before parsing. The policy runs
/// once, before looking up the input root or opening any resource/output file;
/// its narrower manifest and payload bounds then apply. This lets a caller
/// admit a pinned runtime's larger member without widening unrelated builds.
pub fn build_with_policy(
    manifest_path: &Path,
    root: &Path,
    output: &Path,
    policy: impl FnOnce(&Manifest) -> Result<PackLimits, String>,
) -> Result<BuildReport, PackError> {
    let manifest_bytes = read_manifest(manifest_path, MAX_MANIFEST_BYTES as u64)?;
    build_admitted(manifest_path, root, output, manifest_bytes, policy)
}

/// Build an already-owned, complete input inventory.
///
/// The caller admits its language/provider policy separately. This function
/// validates the manifest, all input budgets and identities, and the generated
/// archive before opening `output` with `create_new`. It reads no input files.
/// An output write failure can leave a partial file, as for [`build`].
pub fn build_owned(
    manifest: &Manifest,
    resources: BTreeMap<String, Vec<u8>>,
    output: &Path,
    limits: PackLimits,
) -> Result<BuildReport, PackError> {
    let source = Path::new("<owned manifest>");
    let manifest_bytes = manifest
        .to_json()
        .map_err(|source_error| PackError::Manifest {
            path: source.to_owned(),
            source: source_error,
        })?;
    check_limit(
        "manifest bytes",
        manifest_bytes.len() as u64,
        limits.archive_limits.max_manifest_bytes,
    )?;
    let total = resource_budget(manifest, Path::new("<owned inputs>"), limits)?;
    // write_archive verifies the exact map, lengths and hashes before encoding.
    publish(manifest, &resources, source, output, limits, total)
}

fn build_admitted(
    manifest_path: &Path,
    root: &Path,
    output: &Path,
    manifest_bytes: Vec<u8>,
    policy: impl FnOnce(&Manifest) -> Result<PackLimits, String>,
) -> Result<BuildReport, PackError> {
    let manifest = Manifest::from_json(&manifest_bytes).map_err(|source| PackError::Manifest {
        path: manifest_path.to_owned(),
        source,
    })?;
    let limits = policy(&manifest).map_err(PackError::Profile)?;
    check_limit(
        "manifest bytes",
        manifest_bytes.len() as u64,
        limits.archive_limits.max_manifest_bytes,
    )?;
    let root = canonical_root(root)?;
    // Check the entire input budget before allocating any resource payload.
    let total = resource_budget(&manifest, &root, limits)?;
    let mut resources = BTreeMap::new();
    for (path, spec) in &manifest.resources {
        let input = resource_file(&root, path)?;
        let mut file =
            File::open(&input).map_err(|source| input_io(path, &input, "open", source))?;
        let metadata = file
            .metadata()
            .map_err(|source| input_io(path, &input, "stat open file", source))?;
        if !metadata.is_file() {
            return Err(resource_error(
                path,
                &input,
                "open resource is not a regular file",
            ));
        }
        if metadata.len() != spec.size {
            return Err(resource_error(
                path,
                &input,
                format!(
                    "size differs from manifest: {} != {}",
                    metadata.len(),
                    spec.size,
                ),
            ));
        }
        let size = usize::try_from(spec.size).map_err(|_| PackError::Allocation)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| PackError::Allocation)?;
        bytes.resize(size, 0);
        file.read_exact(&mut bytes)
            .map_err(|source| input_io(path, &input, "read declared bytes", source))?;
        // One extra byte detects a growing file without reading it unboundedly.
        let mut extra = [0];
        if file
            .read(&mut extra)
            .map_err(|source| input_io(path, &input, "check resource EOF", source))?
            != 0
        {
            return Err(resource_error(
                path,
                &input,
                "file changed size while being read",
            ));
        }
        let actual = digest(&bytes);
        if actual != spec.sha256 {
            return Err(resource_error(
                path,
                &input,
                format!("SHA-256 differs from manifest: {actual} != {}", spec.sha256,),
            ));
        }
        resources.insert(path.clone(), bytes);
    }
    publish(&manifest, &resources, manifest_path, output, limits, total)
}

fn resource_budget(manifest: &Manifest, root: &Path, limits: PackLimits) -> Result<u64, PackError> {
    check_limit(
        "resource count",
        manifest.resources.len() as u64,
        limits.archive_limits.max_entries,
    )?;
    let mut total = 0_u64;
    for (path, spec) in &manifest.resources {
        check_limit(
            "resource bytes",
            spec.size,
            limits.archive_limits.max_entry_bytes,
        )?;
        total = total
            .checked_add(spec.size)
            .ok_or_else(|| PackError::Resource {
                resource: path.clone(),
                path: root.join(path),
                reason: "declared input size overflows u64".to_owned(),
            })?;
        check_limit("input bytes", total, limits.max_input_bytes)?;
        check_limit(
            "total resource bytes",
            total,
            limits.archive_limits.max_total_uncompressed_bytes,
        )?;
    }
    Ok(total)
}

fn publish(
    manifest: &Manifest,
    resources: &BTreeMap<String, Vec<u8>>,
    manifest_path: &Path,
    output: &Path,
    limits: PackLimits,
    total: u64,
) -> Result<BuildReport, PackError> {
    let archive_bytes = write_archive(Cursor::new(Vec::new()), manifest, resources)?.into_inner();
    let mut generated =
        Archive::open_with_limits(Cursor::new(&archive_bytes), limits.archive_limits)?;
    generated.verify_all()?;
    let canonical = manifest.to_json().map_err(|source| PackError::Manifest {
        path: manifest_path.to_owned(),
        source,
    })?;
    let report = BuildReport {
        archive_bytes: archive_bytes.len() as u64,
        resource_count: resources.len(),
        uncompressed_bytes: total,
        manifest_sha256: digest(&canonical),
        archive_sha256: digest(&archive_bytes),
    };
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|source| io_error("create archive", output, source))?;
    destination
        .write_all(&archive_bytes)
        .map_err(|source| io_error("write archive", output, source))?;
    destination
        .flush()
        .map_err(|source| io_error("flush archive", output, source))?;
    Ok(report)
}

fn read_manifest(path: &Path, limit: u64) -> Result<Vec<u8>, PackError> {
    let metadata = fs::metadata(path).map_err(|source| io_error("stat manifest", path, source))?;
    if !metadata.is_file() {
        return Err(io_error(
            "read manifest",
            path,
            io::Error::other("manifest is not a regular file"),
        ));
    }
    let limit = limit.min(MAX_MANIFEST_BYTES as u64);
    check_limit("manifest bytes", metadata.len(), limit)?;
    let file = File::open(path).map_err(|source| io_error("open manifest", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("stat open manifest", path, source))?;
    if !metadata.is_file() {
        return Err(io_error(
            "read manifest",
            path,
            io::Error::other("manifest is not a regular file"),
        ));
    }
    check_limit("manifest bytes", metadata.len(), limit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(metadata.len()).map_err(|_| PackError::Allocation)?)
        .map_err(|_| PackError::Allocation)?;
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read manifest", path, source))?;
    check_limit("manifest bytes", bytes.len() as u64, limit)?;
    Ok(bytes)
}

fn canonical_root(root: &Path) -> Result<PathBuf, PackError> {
    if root.as_os_str().is_empty() {
        return Err(PackError::Root {
            path: root.to_owned(),
            reason: "root is empty",
        });
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|source| io_error("stat input root", root, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PackError::Root {
            path: root.to_owned(),
            reason: "root must be a directory and cannot be a symlink",
        });
    }
    fs::canonicalize(root).map_err(|source| io_error("resolve input root", root, source))
}

fn resource_file(root: &Path, resource: &str) -> Result<PathBuf, PackError> {
    ResourcePath::new(resource)
        .map_err(|source| resource_error(resource, root, source.to_string()))?;
    let mut input = root.to_owned();
    let mut components = resource.split('/').peekable();
    while let Some(component) = components.next() {
        input.push(component);
        let metadata = fs::symlink_metadata(&input)
            .map_err(|source| input_io(resource, &input, "stat component", source))?;
        if metadata.file_type().is_symlink() {
            return Err(resource_error(
                resource,
                &input,
                "symlink resource components are forbidden",
            ));
        }
        if components.peek().is_some() {
            if !metadata.is_dir() {
                return Err(resource_error(
                    resource,
                    &input,
                    "intermediate resource component is not a directory",
                ));
            }
        } else if !metadata.is_file() {
            return Err(resource_error(
                resource,
                &input,
                "resource is not a regular file",
            ));
        }
    }
    let resolved = fs::canonicalize(&input)
        .map_err(|source| input_io(resource, &input, "resolve resource", source))?;
    if !resolved.starts_with(root) {
        return Err(resource_error(
            resource,
            &input,
            "resource escaped input root",
        ));
    }
    Ok(resolved)
}

fn check_limit(limit: &'static str, actual: u64, maximum: u64) -> Result<(), PackError> {
    if actual > maximum {
        return Err(PackError::Limit {
            limit,
            actual,
            maximum,
        });
    }
    Ok(())
}
fn io_error(action: &'static str, path: &Path, source: io::Error) -> PackError {
    PackError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}
fn resource_error(resource: &str, path: &Path, reason: impl Into<String>) -> PackError {
    PackError::Resource {
        resource: resource.to_owned(),
        path: path.to_owned(),
        reason: reason.into(),
    }
}
fn input_io(resource: &str, path: &Path, action: &str, source: io::Error) -> PackError {
    resource_error(resource, path, format!("{action}: {source}"))
}

#[cfg(test)]
mod owned_tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        directory: PathBuf,
        manifest: Manifest,
        resources: BTreeMap<String, Vec<u8>>,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-owned-inputs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let resources = BTreeMap::from([
                ("app/main.lua".into(), b"return 42\n".to_vec()),
                ("app/data,one.txt".into(), b"archive data\n".to_vec()),
            ]);
            let specifications: BTreeMap<_, _> = resources
                .iter()
                .map(|(key, bytes)| {
                    (
                        key,
                        json!({"size": bytes.len(), "sha256": digest(bytes), "compression": "deflate"}),
                    )
                })
                .collect();
            let manifest = Manifest::from_json(
                &serde_json::to_vec(&json!({
                    "schema_version": 0, "app_id": "owned.inputs", "entrypoint": "main",
                    "targets": {"mac": {"os": "macos", "arch": "aarch64", "minimum_os_version": "14.0",
                        "abi": {"family": "darwin"}, "page_sizes": [4096], "cpu_features": []}},
                    "resources": specifications,
                    "runtimes": {"lua": {"target": "mac", "build_id": "test-lua",
                        "abi": {"language": "lua", "version": {"major": 5, "minor": 4, "patch": 8},
                            "integer_bits": 64, "number": "float64"},
                        "provisioning": {"mode": "host", "runtime_library": "/test/liblua.dylib",
                            "stdlib": "/test/lua", "discovery": "explicit_paths"}, "required_features": []}},
                    "components": {"main": {"runtime": "lua", "entry_point": "app/main.lua", "native_modules": []}},
                    "native_modules": {}, "host_imports": {},
                }))
                .unwrap(),
            )
            .unwrap();
            Self {
                directory,
                manifest,
                resources,
            }
        }

        fn output(&self, name: &str) -> PathBuf {
            self.directory.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[test]
    fn owned_and_filesystem_inputs_produce_identical_archives_and_reports() {
        let fixture = Fixture::new();
        let root = fixture.output("source");
        fs::create_dir_all(root.join("app")).unwrap();
        for (key, bytes) in &fixture.resources {
            fs::write(root.join(key), bytes).unwrap();
        }
        let manifest_path = fixture.output("manifest.json");
        fs::write(&manifest_path, fixture.manifest.to_json().unwrap()).unwrap();
        let file_output = fixture.output("files.glue");
        let owned_output = fixture.output("owned.glue");
        let file_report = build(&manifest_path, &root, &file_output).unwrap();
        let owned_report = build_owned(
            &fixture.manifest,
            fixture.resources.clone(),
            &owned_output,
            PackLimits::default(),
        )
        .unwrap();
        assert_eq!(owned_report, file_report);
        assert_eq!(
            fs::read(file_output).unwrap(),
            fs::read(&owned_output).unwrap()
        );
        let bytes = fs::read(owned_output).unwrap();
        assert_eq!(owned_report.archive_sha256, digest(&bytes));
        let serialized = serde_json::to_value(&owned_report).unwrap();
        assert_eq!(serialized["archive_sha256"], owned_report.archive_sha256);
        assert_eq!(serialized["resource_count"], 2);
        let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
        for (key, expected) in &fixture.resources {
            assert_eq!(archive.read_resource(key).unwrap(), *expected);
        }
    }

    #[test]
    fn owned_input_identity_and_inventory_failures_finish_before_publication() {
        let fixture = Fixture::new();
        for mode in 0..5 {
            let mut resources = fixture.resources.clone();
            match mode {
                0 => {
                    resources.remove("app/data,one.txt");
                }
                1 => {
                    resources.insert("app/undeclared.txt".into(), Vec::new());
                }
                2 => {
                    resources.get_mut("app/main.lua").unwrap()[0] ^= 1;
                }
                3 => {
                    resources.get_mut("app/main.lua").unwrap().push(0);
                }
                _ => {
                    let bytes = resources.remove("app/data,one.txt").unwrap();
                    resources.insert("app/substituted.txt".into(), bytes);
                }
            }
            let absent = fixture.output(&format!("absent-{mode}.glue"));
            assert!(
                build_owned(
                    &fixture.manifest,
                    resources.clone(),
                    &absent,
                    PackLimits::default()
                )
                .is_err()
            );
            assert!(!absent.exists());
            let existing = fixture.output(&format!("existing-{mode}.glue"));
            fs::write(&existing, b"preserve user content").unwrap();
            assert!(
                build_owned(
                    &fixture.manifest,
                    resources,
                    &existing,
                    PackLimits::default()
                )
                .is_err()
            );
            assert_eq!(fs::read(existing).unwrap(), b"preserve user content");
        }
    }

    #[test]
    fn owned_declaration_and_generated_archive_limits_finish_before_publication() {
        let fixture = Fixture::new();
        let limits = [
            PackLimits {
                max_input_bytes: 1,
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_manifest_bytes: 1,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_entry_bytes: 1,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_total_uncompressed_bytes: 1,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_entries: 1,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_archive_bytes: 1,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
            PackLimits {
                archive_limits: ArchiveLimits {
                    max_compressed_entry_bytes: 0,
                    ..ArchiveLimits::default()
                },
                ..PackLimits::default()
            },
        ];
        for (number, limits) in limits.into_iter().enumerate() {
            let output = fixture.output(&format!("bounded-{number}.glue"));
            assert!(
                build_owned(
                    &fixture.manifest,
                    fixture.resources.clone(),
                    &output,
                    limits
                )
                .is_err()
            );
            assert!(!output.exists());
        }
        let mut invalid = fixture.manifest.clone();
        invalid.schema_version = 99;
        let output = fixture.output("invalid.glue");
        assert!(matches!(
            build_owned(
                &invalid,
                fixture.resources.clone(),
                &output,
                PackLimits::default()
            ),
            Err(PackError::Manifest { .. })
        ));
        assert!(!output.exists());
    }

    #[test]
    fn owned_valid_input_preserves_existing_outputs() {
        let fixture = Fixture::new();
        let output = fixture.output("existing.glue");
        fs::write(&output, b"existing output").unwrap();
        assert!(
            build_owned(
                &fixture.manifest,
                fixture.resources.clone(),
                &output,
                PackLimits::default()
            )
            .is_err()
        );
        assert_eq!(fs::read(output).unwrap(), b"existing output");
    }

    #[cfg(unix)]
    #[test]
    fn owned_valid_input_does_not_follow_output_symlinks() {
        let fixture = Fixture::new();
        let original = fixture.output("original");
        fs::write(&original, b"preserve original").unwrap();
        let output = fixture.output("output-link.glue");
        std::os::unix::fs::symlink(&original, &output).unwrap();
        assert!(
            build_owned(
                &fixture.manifest,
                fixture.resources.clone(),
                &output,
                PackLimits::default()
            )
            .is_err()
        );
        assert_eq!(fs::read(original).unwrap(), b"preserve original");
        assert!(
            fs::symlink_metadata(output)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
