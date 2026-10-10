//! Explicit host layout for the same pinned stock PBS bootstrap fixture.
//!
//! This checks the library and six startup source files and requires their
//! bytecode cache directories to be absent. It does not certify the rest of the
//! installed standard library or provide runtime discovery.
//! Python subsequently opens startup sources by path, so the experiment must
//! keep the installation immutable (the harness uses a read-only mount).

#![cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )),
    allow(dead_code)
)]

use super::bundle::{MODULE_SPECS, RUNTIME_LIBRARY_SHA256};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path},
};

pub(super) const MAX_PATH_BYTES: usize = 4096;
const LIBRARY_SUFFIX: &str = "/lib/libpython3.13.so.1.0";
const STDLIB_SUFFIX: &str = "/lib/python3.13";
const SOURCE_PREFIX: &str = "install/lib/python3.13/";
const LIBRARY_SIZE: u64 = 73_563_968;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Config {
    pub prefix: String,
    pub library: String,
    pub stdlib: String,
}

/// Retain the verified descriptors until interpreter finalization. The runtime
/// library may be loaded through its descriptor rather than reopened by path.
#[derive(Debug)]
pub(super) struct VerifiedHost {
    pub config: Config,
    pub library: File,
    _sources: Vec<File>,
    _directories: Vec<File>,
}

impl Config {
    pub(super) fn parse(prefix: &str) -> Result<Self, String> {
        validate_path(prefix)?;
        // The fixed layout would produce a repeated slash for the root prefix.
        if prefix == "/" {
            return Err("host prefix must name an installation directory".into());
        }
        let library = format!("{prefix}{LIBRARY_SUFFIX}");
        let stdlib = format!("{prefix}{STDLIB_SUFFIX}");
        validate_path(&library)?;
        validate_path(&stdlib)?;
        Ok(Self {
            prefix: prefix.into(),
            library,
            stdlib,
        })
    }

    /// Require the exact library and six reviewed startup sources without
    /// following symlinks or admitting existing startup bytecode caches. Byte
    /// counts are checked before and during hashing; the library is streamed
    /// rather than copied into a 70 MiB allocation.
    pub(super) fn verify(&self) -> Result<VerifiedHost, String> {
        // Fields are visible to the fixture caller, so recheck the fixed layout.
        if Self::parse(&self.prefix)? != *self {
            return Err("host configuration differs from the fixed installation layout".into());
        }
        let mut directories = open_directories(Path::new(&self.stdlib))?;
        let encodings = Path::new(&self.stdlib).join("encodings");
        directories.append(&mut open_directories(&encodings)?);
        require_cache_absent(&Path::new(&self.stdlib).join("__pycache__"))?;
        require_cache_absent(&encodings.join("__pycache__"))?;
        let (library, mut library_dirs) = verified_file(
            Path::new(&self.library),
            LIBRARY_SIZE,
            RUNTIME_LIBRARY_SHA256,
        )?;
        directories.append(&mut library_dirs);
        let mut sources = Vec::with_capacity(MODULE_SPECS.len());
        for spec in &MODULE_SPECS {
            let relative = spec
                .source_path
                .strip_prefix(SOURCE_PREFIX)
                .ok_or("reviewed startup source is outside the fixed standard library")?;
            let source = format!("{}/{relative}", self.stdlib);
            validate_path(&source)?;
            let (file, mut source_dirs) =
                verified_file(Path::new(&source), spec.source_size, spec.source_sha256)?;
            sources.push(file);
            directories.append(&mut source_dirs);
        }
        Ok(VerifiedHost {
            config: self.clone(),
            library,
            _sources: sources,
            _directories: directories,
        })
    }
}

fn require_cache_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "host startup bytecode cache is unsupported: {}",
            path.display()
        )),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(format!(
            "inspect host startup bytecode cache {}: {error}",
            path.display()
        )),
    }
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.is_ascii()
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte < b' ' || byte == 0x7f || byte == b'\\')
        || (path != "/" && path.ends_with('/'))
        || path.contains("//")
        || path
            .split('/')
            .skip(1)
            .any(|part| part == "." || part == "..")
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("host paths must be canonical absolute ASCII paths of at most 4096 bytes without control characters or backslashes".into());
    }
    Ok(())
}

fn open_directories(path: &Path) -> Result<Vec<File>, String> {
    let text = path.to_str().ok_or("host directory path must be ASCII")?;
    validate_path(text)?;
    let mut current = std::path::PathBuf::from("/");
    let mut directories = vec![open_checked(&current, true)?];
    for component in path.components() {
        if let Component::Normal(name) = component {
            current.push(name);
            directories.push(open_checked(&current, true)?);
        }
    }
    Ok(directories)
}

fn open_checked(path: &Path, directory: bool) -> Result<File, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("host path {}: {error}", path.display()))?;
    require_kind(path, &before, directory)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // These flags are supported through the safe standard-library API.
        // NONBLOCK prevents a raced-in FIFO/device from blocking an open.
        let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
        options.custom_flags(if directory {
            flags | libc::O_DIRECTORY
        } else {
            flags
        });
    }
    let file = options.open(path).map_err(|error| {
        format!(
            "open host path {} without symlinks: {error}",
            path.display()
        )
    })?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect open host path {}: {error}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("recheck host path {}: {error}", path.display()))?;
    require_kind(path, &opened, directory)?;
    require_kind(path, &after, directory)?;
    if !same_file(&before, &opened) || !same_file(&opened, &after) {
        return Err(format!("host path identity changed: {}", path.display()));
    }
    Ok(file)
}

fn require_kind(path: &Path, metadata: &Metadata, directory: bool) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(format!(
            "host path {} must be a {} without symlinks",
            path.display(),
            if directory {
                "directory"
            } else {
                "regular file"
            }
        ));
    }
    Ok(())
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.file_type() == right.file_type()
            && left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
    }
}

fn verified_file(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(File, Vec<File>), String> {
    let directories = open_directories(path.parent().ok_or("host file has no parent")?)?;
    let mut file = open_checked(path, false)?;
    if file
        .metadata()
        .map_err(|error| format!("inspect host file {}: {error}", path.display()))?
        .len()
        != expected_size
    {
        return Err(format!("host file size mismatch: {}", path.display()));
    }
    let maximum = expected_size
        .checked_add(1)
        .ok_or("host file size bound overflow")?;
    let mut input = (&mut file).take(maximum);
    let mut sha256 = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("hash host file {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        count += read as u64;
        sha256.update(&buffer[..read]);
    }
    let actual_sha256: String = sha256
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if count != expected_size || actual_sha256 != expected_sha256 {
        return Err(format!("host file identity mismatch: {}", path.display()));
    }
    if file
        .metadata()
        .map_err(|error| format!("recheck host file {}: {error}", path.display()))?
        .len()
        != expected_size
    {
        return Err(format!(
            "host file size changed while hashing: {}",
            path.display()
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewind host file {}: {error}", path.display()))?;
    Ok((file, directories))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            // /tmp can itself be a symlink on macOS; test the real directory.
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "glue-python-host-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn prefix_resolves_only_the_fixed_profile() {
        let config = Config::parse("/host Python").unwrap();
        assert_eq!(config.prefix, "/host Python");
        assert_eq!(config.library, "/host Python/lib/libpython3.13.so.1.0");
        assert_eq!(config.stdlib, "/host Python/lib/python3.13");
    }

    #[test]
    fn rejects_path_normalization_and_escape_forms() {
        for path in [
            "",
            "/",
            "relative",
            "//host",
            "/host/",
            "/host//python",
            "/host/./python",
            "/host/../python",
            "/host\\python",
            "/host\npython",
            "/host\0python",
            "/höst",
            "C:/host",
        ] {
            assert!(Config::parse(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn bounds_expanded_paths_not_only_the_prefix() {
        let maximum = MAX_PATH_BYTES - LIBRARY_SUFFIX.len();
        assert!(Config::parse(&format!("/{}", "a".repeat(maximum - 1))).is_ok());
        assert!(Config::parse(&format!("/{}", "a".repeat(maximum))).is_err());
        assert!(Config::parse(&format!("/{}", "a".repeat(MAX_PATH_BYTES))).is_err());
    }

    #[test]
    fn revalidates_mutated_config_fields_before_filesystem_access() {
        let mut config = Config::parse("/absent-host-prefix").unwrap();
        config.library = "/another-library.so".into();
        assert!(
            config
                .verify()
                .unwrap_err()
                .contains("fixed installation layout")
        );
    }

    #[test]
    fn streams_verified_file_and_returns_rewound_handle() {
        let fixture = Fixture::new();
        let data = vec![0x59; 64 * 1024 + 7];
        let path = fixture.file("source.py", &data);
        let (mut file, directories) =
            verified_file(&path, data.len() as u64, &glue_format::digest(&data)).unwrap();
        assert!(!directories.is_empty());
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn rejects_short_long_and_hash_mismatched_files() {
        let fixture = Fixture::new();
        let path = fixture.file("source.py", b"abc");
        let hash = glue_format::digest(b"abc");
        assert!(
            verified_file(&path, 2, &hash)
                .unwrap_err()
                .contains("size mismatch")
        );
        assert!(
            verified_file(&path, 4, &hash)
                .unwrap_err()
                .contains("size mismatch")
        );
        assert!(
            verified_file(&path, 3, &"0".repeat(64))
                .unwrap_err()
                .contains("identity mismatch")
        );
    }

    #[test]
    fn rejects_missing_files_and_directories_used_as_files() {
        let fixture = Fixture::new();
        assert!(verified_file(&fixture.0.join("absent"), 0, &glue_format::digest(b"")).is_err());
        assert!(
            verified_file(&fixture.0, 0, &glue_format::digest(b""))
                .unwrap_err()
                .contains("regular file")
        );
    }

    #[test]
    fn rejects_regular_file_as_directory_ancestor() {
        let fixture = Fixture::new();
        let path = fixture.file("ordinary-file", b"abc");
        assert!(open_directories(&path).unwrap_err().contains("directory"));
    }

    #[test]
    fn accepts_only_absent_startup_cache_paths() {
        let fixture = Fixture::new();
        assert!(require_cache_absent(&fixture.0.join("__pycache__")).is_ok());
    }

    #[test]
    fn rejects_directory_and_file_startup_caches() {
        let fixture = Fixture::new();
        let directory = fixture.0.join("__pycache__");
        fs::create_dir(&directory).unwrap();
        assert_eq!(
            require_cache_absent(&directory).unwrap_err(),
            format!(
                "host startup bytecode cache is unsupported: {}",
                directory.display()
            )
        );
        let file = fixture.file("file-cache", b"");
        assert!(
            require_cache_absent(&file)
                .unwrap_err()
                .starts_with("host startup bytecode cache is unsupported:")
        );
    }

    #[test]
    fn rejects_each_startup_cache_before_opening_the_library() {
        for cache in ["__pycache__", "encodings/__pycache__"] {
            let fixture = Fixture::new();
            let stdlib = fixture.0.join("lib/python3.13");
            fs::create_dir_all(stdlib.join("encodings")).unwrap();
            let path = stdlib.join(cache);
            fs::create_dir(&path).unwrap();
            // No runtime library exists. Cache rejection must occur first.
            let config = Config::parse(fixture.0.to_str().unwrap()).unwrap();
            assert_eq!(
                config.verify().unwrap_err(),
                format!(
                    "host startup bytecode cache is unsupported: {}",
                    path.display()
                )
            );
        }
    }

    #[test]
    fn rejects_startup_cache_lookup_errors_other_than_enoent() {
        let fixture = Fixture::new();
        let file = fixture.file("ordinary-file", b"");
        let error = require_cache_absent(&file.join("__pycache__")).unwrap_err();
        assert!(error.starts_with("inspect host startup bytecode cache"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_startup_cache_symlinks_even_when_dangling() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let cache = fixture.0.join("__pycache__");
        symlink(fixture.0.join("missing-target"), &cache).unwrap();
        assert!(
            require_cache_absent(&cache)
                .unwrap_err()
                .starts_with("host startup bytecode cache is unsupported:")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_file_and_directory_symlinks() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let source = fixture.file("source.py", b"abc");
        let alias = fixture.0.join("source-alias.py");
        symlink(&source, &alias).unwrap();
        assert!(
            verified_file(&alias, 3, &glue_format::digest(b"abc"))
                .unwrap_err()
                .contains("without symlinks")
        );
        let child = fixture.0.join("stdlib");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("module.py"), b"abc").unwrap();
        let alias = fixture.0.join("stdlib-alias");
        symlink(&child, &alias).unwrap();
        assert!(
            verified_file(&alias.join("module.py"), 3, &glue_format::digest(b"abc"))
                .unwrap_err()
                .contains("without symlinks")
        );
    }
}
