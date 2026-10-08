//! Build-time packaging of an explicit manifest inventory.
//!
//! This module performs ordinary filesystem reads on the builder. It never
//! discovers, installs, downloads or executes missing dependencies, and it is
//! separate from the runtime's read-only archive reader.

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

#[derive(Clone, Debug, Eq, PartialEq)]
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
    let manifest = Manifest::from_json(&manifest_bytes).map_err(|source| PackError::Manifest {
        path: manifest_path.to_owned(),
        source,
    })?;
    let root = canonical_root(root)?;
    // Check the entire input budget before allocating any resource payload.
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
    let archive_bytes = write_archive(Cursor::new(Vec::new()), &manifest, &resources)?.into_inner();
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
