//! Build-time publication of the two exact pinned Python host prerequisite trees.
//!
//! Preparation inspects an explicit artifact and owns every admitted byte before
//! publication. It never runs Python or discovers an installation. These trees
//! contain embedding prerequisites, rather than complete Python installations.

use super::{PackError, python_template::TemplateFileIdentity};
use glue_runtime_python::packaging::host_prerequisites::{
    FileIdentity, HostPrerequisiteProvenance,
};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

#[cfg(unix)]
use super::{check_limit, io_error};
#[cfg(unix)]
use glue_format::{MAX_MANIFEST_BYTES, digest};
#[cfg(unix)]
use glue_runtime_python::packaging::{host_prerequisites, template::HostProvider};
#[cfg(unix)]
use std::{
    collections::BTreeSet,
    fs::{self, File, FileTimes, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};

#[cfg(unix)]
const FILE_MODE: u32 = 0o444;
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o555;
#[cfg(unix)]
const STOCK_MTIME_SECONDS: u64 = 1_704_067_200;

#[derive(Clone, Copy, Debug)]
pub enum HostInput<'a> {
    Full { artifact: &'a Path },
    Install { artifact: &'a Path },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostReport {
    pub provider: String,
    pub prefix: String,
    pub provenance: HostPrerequisiteProvenance,
    /// Identity of the published provenance, including its trailing JSON LF.
    pub provenance_file: TemplateFileIdentity,
    /// All payload paths are relative to the prepared prefix.
    pub files: BTreeMap<String, FileIdentity>,
    pub file_count: usize,
    pub payload_bytes: u64,
    /// Includes the new prefix itself; excludes its already existing parent.
    pub directory_count: usize,
    pub file_mode: u32,
    pub directory_mode: u32,
    /// Publication sets payload, provenance and directory mtimes to this epoch.
    pub mtime_seconds: u64,
}

/// Prepare a pinned host prerequisite tree at a new absolute Unix prefix.
///
/// Prefix admission precedes input access. Complete artifact/content validation
/// finishes before the exclusive output creation. Files receive stock mtimes
/// and read-only permissions; provenance is written last, then directories are
/// frozen from leaves to the root. Input and output-parent trees must stay stable
/// throughout preparation. Publication I/O failure can leave a partial newly
/// created tree and never removes or replaces unrelated paths.
#[cfg(unix)]
pub fn prepare(input: HostInput<'_>, output: &Path) -> Result<HostReport, PackError> {
    let (artifact, provider) = match input {
        HostInput::Full { artifact } => (artifact, HostProvider::Full),
        HostInput::Install { artifact } => (artifact, HostProvider::InstallOnly),
    };
    let prefix = output.to_str().ok_or_else(|| {
        PackError::Profile("host prerequisite prefix must be an absolute UTF-8 ASCII path".into())
    })?;
    host_prerequisites::validate_prefix(prefix, provider).map_err(PackError::Profile)?;
    let mut input = regular_file(artifact)?;
    let owned = match provider {
        HostProvider::Full => host_prerequisites::full(&mut input),
        HostProvider::InstallOnly => host_prerequisites::install(&mut input),
    }
    .map_err(PackError::Profile)?;
    publish(owned, output)
}

/// Permission and mtime publication semantics are admitted only on Unix.
#[cfg(not(unix))]
pub fn prepare(_input: HostInput<'_>, _output: &Path) -> Result<HostReport, PackError> {
    Err(PackError::Profile(
        "host prerequisite publication is unsupported on non-Unix builders".into(),
    ))
}

#[cfg(unix)]
fn publish(
    owned: host_prerequisites::HostPrerequisites,
    output: &Path,
) -> Result<HostReport, PackError> {
    host_prerequisites::validate_contents(&owned).map_err(PackError::Profile)?;
    let directories = publication_directories(&owned.files);
    let payload_bytes = owned.files.values().try_fold(0_u64, |sum, bytes| {
        sum.checked_add(bytes.len() as u64)
            .ok_or(PackError::Allocation)
    })?;
    let mut provenance_bytes = serde_json::to_vec(&owned.provenance)
        .map_err(|error| PackError::Profile(format!("serialize host provenance: {error}")))?;
    provenance_bytes.push(b'\n');
    check_limit(
        "host provenance bytes",
        provenance_bytes.len() as u64,
        MAX_MANIFEST_BYTES as u64,
    )?;
    let report = HostReport {
        provider: owned.provenance.provider.clone(),
        prefix: output
            .to_str()
            .expect("prefix admission requires UTF-8")
            .into(),
        provenance_file: TemplateFileIdentity {
            path: "provenance.json".into(),
            size: provenance_bytes.len() as u64,
            sha256: digest(&provenance_bytes),
        },
        files: owned.provenance.files.clone(),
        file_count: owned.files.len(),
        payload_bytes,
        directory_count: directories.len(),
        file_mode: FILE_MODE,
        directory_mode: DIRECTORY_MODE,
        mtime_seconds: STOCK_MTIME_SECONDS,
        provenance: owned.provenance,
    };

    create_output(output)?;
    for relative in directories
        .iter()
        .filter(|path| !path.as_os_str().is_empty())
    {
        let destination = output.join(relative);
        fs::create_dir(&destination)
            .map_err(|source| io_error("create host directory", &destination, source))?;
    }
    for (relative, bytes) in &owned.files {
        write_new(&output.join(relative), bytes)?;
    }
    write_new(&output.join("provenance.json"), &provenance_bytes)?;
    freeze_directories(output, &directories)?;
    Ok(report)
}

#[cfg(unix)]
fn regular_file(path: &Path) -> Result<File, PackError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat host artifact", path, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io_error(
            "read host artifact",
            path,
            std::io::Error::other("host artifact must be a regular file and cannot be a symlink"),
        ));
    }
    let file = File::open(path).map_err(|source| io_error("open host artifact", path, source))?;
    if !file
        .metadata()
        .map_err(|source| io_error("stat open host artifact", path, source))?
        .is_file()
    {
        return Err(io_error(
            "read host artifact",
            path,
            std::io::Error::other("open host artifact is not a regular file"),
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn publication_directories(files: &BTreeMap<String, Vec<u8>>) -> BTreeSet<PathBuf> {
    let mut directories = BTreeSet::from([PathBuf::new()]);
    for relative in files.keys() {
        let mut parent = Path::new(relative).parent();
        while let Some(directory) = parent {
            directories.insert(directory.into());
            parent = directory.parent();
        }
    }
    directories
}

#[cfg(unix)]
fn create_output(output: &Path) -> Result<(), PackError> {
    let parent = output
        .parent()
        .expect("admitted absolute prefix has a parent");
    let metadata =
        fs::metadata(parent).map_err(|source| io_error("stat host parent", parent, source))?;
    if !metadata.is_dir() {
        return Err(io_error(
            "create host prefix",
            output,
            std::io::Error::other("host prefix parent is not a directory"),
        ));
    }
    fs::create_dir(output).map_err(|source| io_error("create host prefix", output, source))
}

#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), PackError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create host file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write host file", path, source))?;
    file.flush()
        .map_err(|source| io_error("flush host file", path, source))?;
    set_publication_metadata(&file, path, FILE_MODE)
}

#[cfg(unix)]
fn freeze_directories(output: &Path, directories: &BTreeSet<PathBuf>) -> Result<(), PackError> {
    // A parent's path sorts before all its descendants, so reversing this order
    // freezes every child before its parent, including the prefix itself last.
    for relative in directories.iter().rev() {
        let destination = output.join(relative);
        let directory = File::open(&destination)
            .map_err(|source| io_error("open host directory", &destination, source))?;
        set_publication_metadata(&directory, &destination, DIRECTORY_MODE)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_publication_metadata(file: &File, path: &Path, mode: u32) -> Result<(), PackError> {
    file.set_times(
        FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(STOCK_MTIME_SECONDS)),
    )
    .map_err(|source| io_error("set host mtime", path, source))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set host permissions", path, source))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::{ffi::OsStringExt, fs::MetadataExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-python-host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory)
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.0.join(relative)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fn restore_directories(path: &Path) {
                if fs::symlink_metadata(path).unwrap().is_dir() {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
                    for entry in fs::read_dir(path).unwrap() {
                        restore_directories(&entry.unwrap().path());
                    }
                }
            }
            restore_directories(&self.0);
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn input(path: &Path, install: bool) -> HostInput<'_> {
        if install {
            HostInput::Install { artifact: path }
        } else {
            HostInput::Full { artifact: path }
        }
    }

    #[test]
    fn invalid_prefix_is_rejected_before_artifact_access() {
        let fixture = Fixture::new();
        let missing = fixture.path("absent artifact");
        for install in [false, true] {
            for prefix in [
                "relative",
                "/invalid/../prefix",
                "/invalid//prefix",
                "/invalid\\prefix",
                "/invalid/prefixé",
            ] {
                assert!(matches!(
                    prepare(input(&missing, install), Path::new(prefix)),
                    Err(PackError::Profile(_))
                ));
            }
            let invalid_utf8 =
                PathBuf::from(std::ffi::OsString::from_vec(b"/invalid/\xff".to_vec()));
            assert!(matches!(
                prepare(input(&missing, install), &invalid_utf8),
                Err(PackError::Profile(_))
            ));
        }
        assert!(!missing.exists());
    }

    #[test]
    fn directory_and_symlink_artifacts_are_rejected_before_publication() {
        let fixture = Fixture::new();
        let directory = fixture.path("artifact directory");
        fs::create_dir(&directory).unwrap();
        let artifact = fixture.path("artifact");
        fs::write(&artifact, b"not a pinned stock artifact").unwrap();
        let linked = fixture.path("artifact link");
        std::os::unix::fs::symlink(&artifact, &linked).unwrap();
        let dangling = fixture.path("dangling artifact");
        std::os::unix::fs::symlink(fixture.path("missing target"), &dangling).unwrap();
        let output = fixture.path("output");
        for install in [false, true] {
            for source in [&directory, &linked, &dangling] {
                assert!(matches!(
                    prepare(input(source, install), &output),
                    Err(PackError::Io { .. })
                ));
                assert!(!output.exists());
            }
        }
        assert_eq!(fs::read(artifact).unwrap(), b"not a pinned stock artifact");
    }

    #[test]
    fn invalid_artifacts_preserve_absent_and_existing_outputs() {
        let fixture = Fixture::new();
        let artifact = fixture.path("artifact");
        fs::write(&artifact, b"not a pinned stock artifact").unwrap();
        let absent = fixture.path("absent");
        let existing = fixture.path("existing");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("sentinel"), b"preserved").unwrap();
        for install in [false, true] {
            for output in [&absent, &existing] {
                assert!(matches!(
                    prepare(input(&artifact, install), output),
                    Err(PackError::Profile(_))
                ));
            }
            assert!(!absent.exists());
            assert_eq!(fs::read(existing.join("sentinel")).unwrap(), b"preserved");
            assert_eq!(fs::read_dir(&existing).unwrap().count(), 1);
        }
    }

    #[test]
    fn invalid_owned_contents_are_rejected_before_publication() {
        use glue_runtime_python::packaging::template;

        let fixture = Fixture::new();
        let declared = template::host("/unverified Python", HostProvider::Full).unwrap();
        let facts = declared.provenance;
        let owned = host_prerequisites::HostPrerequisites {
            files: BTreeMap::new(),
            provenance: HostPrerequisiteProvenance {
                schema_version: 0,
                provider: "host-full".into(),
                files: BTreeMap::new(),
                artifact: template::ArtifactIdentity {
                    filename: "invalid-artifact".into(),
                    size: 0,
                    sha256: digest(b""),
                    url: "https://example.invalid".into(),
                },
                artifact_entries: 0,
                artifact_payload_bytes: 0,
                selected_files: 0,
                selected_bytes: 0,
                omitted_files: 0,
                omitted_bytes: 0,
                source_inventory: facts.source_inventory,
                cache_inventory: None,
                profile_build_id: declared.manifest.runtimes["python"].build_id.clone(),
                python_version: facts.producer.python_version,
                target_triple: facts.producer.target_triple,
                full_install_pairing_observed: false,
                runtime_execution_observed: false,
                is_complete_python_installation: false,
                stock_mtime_seconds: STOCK_MTIME_SECONDS,
            },
        };
        let output = fixture.path("prefix");
        assert!(matches!(
            publish(owned, &output),
            Err(PackError::Profile(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn exclusive_output_creation_preserves_files_directories_and_symlinks() {
        let fixture = Fixture::new();
        let file = fixture.path("file");
        fs::write(&file, b"preserved file").unwrap();
        let directory = fixture.path("directory");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("sentinel"), b"preserved directory").unwrap();
        let linked = fixture.path("linked");
        std::os::unix::fs::symlink(&directory, &linked).unwrap();
        let missing_target = fixture.path("missing target");
        let dangling = fixture.path("dangling");
        std::os::unix::fs::symlink(&missing_target, &dangling).unwrap();
        for output in [&file, &directory, &linked, &dangling] {
            assert!(matches!(create_output(output), Err(PackError::Io { .. })));
        }
        assert_eq!(fs::read(file).unwrap(), b"preserved file");
        assert_eq!(
            fs::read(directory.join("sentinel")).unwrap(),
            b"preserved directory"
        );
        assert!(
            fs::symlink_metadata(linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!missing_target.exists());
    }

    #[test]
    fn publication_never_materializes_a_missing_parent() {
        let fixture = Fixture::new();
        let parent = fixture.path("missing parent");
        assert!(matches!(
            create_output(&parent.join("prefix")),
            Err(PackError::Io { .. })
        ));
        assert!(!parent.exists());
        let file_parent = fixture.path("file parent");
        fs::write(&file_parent, b"preserved parent").unwrap();
        assert!(matches!(
            create_output(&file_parent.join("prefix")),
            Err(PackError::Io { .. })
        ));
        assert_eq!(fs::read(file_parent).unwrap(), b"preserved parent");
    }

    #[test]
    fn written_files_have_stock_mtime_readonly_mode_and_exclusive_creation() {
        let fixture = Fixture::new();
        let file = fixture.path("payload");
        write_new(&file, b"host payload\0\xff").unwrap();
        let metadata = fs::metadata(&file).unwrap();
        assert_eq!(metadata.mode() & 0o7777, FILE_MODE);
        assert_eq!(metadata.mtime(), STOCK_MTIME_SECONDS as i64);
        assert_eq!(metadata.mtime_nsec(), 0);
        assert_eq!(fs::read(&file).unwrap(), b"host payload\0\xff");
        assert!(write_new(&file, b"replacement").is_err());
        let linked = fixture.path("linked file");
        std::os::unix::fs::symlink(&file, &linked).unwrap();
        assert!(write_new(&linked, b"replacement").is_err());
        assert_eq!(fs::read(file).unwrap(), b"host payload\0\xff");
    }

    #[test]
    fn directory_freezing_is_complete_and_leaves_the_parent_unchanged() {
        let fixture = Fixture::new();
        let output = fixture.path("prefix");
        let files = BTreeMap::from([
            ("lib/runtime".into(), b"library".to_vec()),
            ("lib/python3.13/encodings/a.py".into(), b"source".to_vec()),
            ("lib/python3.13/site.py".into(), b"source".to_vec()),
        ]);
        let directories = publication_directories(&files);
        assert_eq!(directories.len(), 4);
        create_output(&output).unwrap();
        for relative in directories
            .iter()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir(output.join(relative)).unwrap();
        }
        for (relative, bytes) in &files {
            write_new(&output.join(relative), bytes).unwrap();
        }
        let parent_before = fs::metadata(&fixture.0).unwrap();
        freeze_directories(&output, &directories).unwrap();
        for relative in &directories {
            let metadata = fs::metadata(output.join(relative)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, DIRECTORY_MODE);
            assert_eq!(metadata.mtime(), STOCK_MTIME_SECONDS as i64);
            assert_eq!(metadata.mtime_nsec(), 0);
        }
        let parent_after = fs::metadata(&fixture.0).unwrap();
        assert_eq!(parent_before.mode(), parent_after.mode());
        assert_eq!(parent_before.mtime(), parent_after.mtime());
        assert_eq!(parent_before.mtime_nsec(), parent_after.mtime_nsec());
        for (relative, bytes) in &files {
            assert_eq!(fs::read(output.join(relative)).unwrap(), *bytes);
        }
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn unsupported_publication_precedes_filesystem_access() {
        for input in [
            HostInput::Full {
                artifact: Path::new("missing artifact"),
            },
            HostInput::Install {
                artifact: Path::new("missing artifact"),
            },
        ] {
            let error = prepare(input, Path::new("relative output")).unwrap_err();
            assert!(error.to_string().contains("unsupported on non-Unix"));
        }
    }
}
