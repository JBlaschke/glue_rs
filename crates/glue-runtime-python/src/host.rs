//! Explicit host layout for the same pinned stock PBS bootstrap fixture.
//!
//! The base policy checks the library and six startup source files; archive
//! imports add a bounded reviewed source subset. Their bytecode cache
//! directories must be absent. This does not certify the complete installed
//! standard library or provide runtime discovery. The separate source snapshot
//! policy verifies the complete pinned source projection before initialization;
//! its caller serves owned bytes after host startup instead of reopening them.
//! Python subsequently opens source files by path, so the experiment must
//! keep the installation immutable (the harness uses a read-only mount).

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

use super::bundle::{MODULE_SPECS, RUNTIME_LIBRARY_SHA256};
use glue_format::{Compression, ResourceSpec, validate_resource_paths};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

pub(super) const MAX_PATH_BYTES: usize = 4096;
const LIBRARY_SUFFIX: &str = "/lib/libpython3.13.so.1.0";
const STDLIB_SUFFIX: &str = "/lib/python3.13";
const SOURCE_PREFIX: &str = "install/lib/python3.13/";
const LIBRARY_SIZE: u64 = 73_563_968;
const MAX_IMPORT_SOURCES: usize = 128;
const MAX_IMPORT_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const SNAPSHOT_SOURCE_COUNT: usize = 2174;
const SNAPSHOT_SOURCE_BYTES: u64 = 39_158_056;
const SNAPSHOT_DIRECTORY_COUNT: usize = 202;
const MAX_SNAPSHOT_DIRECTORY_OWNERS: usize = 256;
const INSTALL_SNAPSHOT_SOURCE_COUNT: usize = 1037;
const INSTALL_SNAPSHOT_SOURCE_BYTES: u64 = 15_894_268;
const INSTALL_SNAPSHOT_DIRECTORY_COUNT: usize = 100;
const INSTALL_STARTUP_CACHE_BYTES: u64 = 21_157;
const MAX_INSTALL_RETAINED_OWNERS: usize = 763;
const INSTALL_SOURCE_PINS: &[u8] =
    include_bytes!("../../../fixtures/python-install-host-source-apps/source-pins.json");
const INSTALL_CACHE_PINS: &[u8] =
    include_bytes!("../../../fixtures/python-install-host-source-apps/cache-pins.json");
const INSTALL_CACHE_NAMES: [&str; 3] = [
    "__init__.cpython-313.pyc",
    "aliases.cpython-313.pyc",
    "utf_8.cpython-313.pyc",
];

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

/// The installed sources are immutable owned bytes. Only the legacy startup
/// files and distinct directory owners remain open through finalization.
#[derive(Debug)]
pub(super) struct SourceSnapshot {
    pub verified: VerifiedHost,
    pub files: BTreeMap<String, Vec<u8>>,
}

struct SourceSnapshotLayout {
    files: Vec<(String, PathBuf, ResourceSpec)>,
    directories: BTreeSet<PathBuf>,
    encodings: BTreeSet<String>,
    startup_shadows: BTreeSet<PathBuf>,
}

struct InstallSourceSnapshotLayout {
    sources: SourceSnapshotLayout,
    cache_directory: PathBuf,
    caches: Vec<(PathBuf, ResourceSpec)>,
}

struct ImportSources<'a> {
    files: Vec<(PathBuf, &'a ResourceSpec)>,
    caches: BTreeSet<PathBuf>,
}

/// Image selection is internal to the exact execution profile. Legacy host
/// verifiers always select the original unstripped image.
#[derive(Clone, Copy)]
enum InstallImage {
    Unstripped,
    Stripped,
}

impl InstallImage {
    fn identity(self) -> (u64, &'static str) {
        match self {
            Self::Unstripped => (LIBRARY_SIZE, RUNTIME_LIBRARY_SHA256),
            Self::Stripped => (
                crate::stripped_host::LIBRARY_SIZE,
                crate::stripped_host::LIBRARY_SHA256,
            ),
        }
    }
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

    /// Extend the startup policy with reviewed source pins, relative to the
    /// installed stdlib. Stored means raw host source bytes, not archive data.
    /// All metadata is validated before any host access. The six startup pins
    /// are excluded here; their existing verification order stays unchanged.
    pub(super) fn verify_imports(
        &self,
        pins: &BTreeMap<String, ResourceSpec>,
    ) -> Result<VerifiedHost, String> {
        let imports = self.import_sources(pins)?;
        let mut verified = self.verify()?;
        let (sources, directories) = verify_import_sources(&imports)?;
        verified._sources.extend(sources);
        verified._directories.extend(directories);
        Ok(verified)
    }

    /// Validate every expanded source/cache/shadow path and compiled inventory
    /// bound without inspecting a host path. Existing host profiles do not use
    /// this wider policy.
    pub(super) fn validate_source_snapshot_layout(&self) -> Result<(), String> {
        self.source_snapshot_layout().map(|_| ())
    }

    /// Snapshot the exact full PBS .py projection before the interpreter loads.
    /// Cache checks and startup shadow rejection precede library/source hashing.
    /// Source descriptors close promptly after their owned bytes verify; parent
    /// directory descriptors are deduplicated. As with the legacy host policy,
    /// callers must keep the installation immutable through execution and
    /// finalization; the mapped library remains pinned for process life.
    pub(super) fn verify_source_snapshot(&self) -> Result<SourceSnapshot, String> {
        let layout = self.source_snapshot_layout()?;
        let mut directories = snapshot_prerequisites(&layout, Path::new(&self.stdlib))?;
        // Keep the old library/six-source verifier and its ownership behavior.
        let mut verified = self.verify()?;
        let files = snapshot_sources(&layout.files)?;
        verified._directories.append(&mut directories);
        Ok(SourceSnapshot { verified, files })
    }

    fn source_snapshot_layout(&self) -> Result<SourceSnapshotLayout, String> {
        if Self::parse(&self.prefix)? != *self {
            return Err("host configuration differs from the fixed installation layout".into());
        }
        let specs = super::import_profile::source_specs()?;
        self.source_snapshot_layout_from(
            specs,
            SNAPSHOT_SOURCE_COUNT,
            SNAPSHOT_SOURCE_BYTES,
            SNAPSHOT_DIRECTORY_COUNT,
        )
    }

    /// Admit the independently pinned stock install-only source/cache layout
    /// without inspecting paths. The full-source profile keeps its own pins and
    /// rejects every cache; this policy requires the three stock startup caches.
    pub(super) fn validate_install_source_snapshot_layout(&self) -> Result<(), String> {
        self.install_source_snapshot_layout().map(|_| ())
    }

    /// Verify exact install-only startup caches and sources before loading. The
    /// cache and six startup descriptors, plus deduplicated directory owners,
    /// remain live through finalization. Snapshot sources become owned bytes.
    pub(super) fn verify_install_source_snapshot(&self) -> Result<SourceSnapshot, String> {
        self.verify_install_source_snapshot_with_image(InstallImage::Unstripped)
    }

    /// The separate stripped metadata profile retains the same independently
    /// compared sources/cache layout, but requires its own exact library bytes.
    pub(super) fn verify_stripped_install_source_snapshot(&self) -> Result<SourceSnapshot, String> {
        self.verify_install_source_snapshot_with_image(InstallImage::Stripped)
    }

    fn verify_install_source_snapshot_with_image(
        &self,
        image: InstallImage,
    ) -> Result<SourceSnapshot, String> {
        let layout = self.install_source_snapshot_layout()?;
        let (mut directories, mut caches) =
            install_snapshot_prerequisites(&layout, Path::new(&self.stdlib))?;
        let mut verified = self.verify_install_startup(image)?;
        let files = snapshot_sources(&layout.sources.files)?;
        verified._sources.append(&mut caches);
        verified._directories.append(&mut directories);
        Ok(SourceSnapshot { verified, files })
    }

    fn install_source_snapshot_layout(&self) -> Result<InstallSourceSnapshotLayout, String> {
        if Self::parse(&self.prefix)? != *self {
            return Err("host configuration differs from the fixed installation layout".into());
        }
        let sources = self.source_snapshot_layout_from(
            install_source_specs()?,
            INSTALL_SNAPSHOT_SOURCE_COUNT,
            INSTALL_SNAPSHOT_SOURCE_BYTES,
            INSTALL_SNAPSHOT_DIRECTORY_COUNT,
        )?;
        let cache_directory = Path::new(&self.stdlib).join("encodings/__pycache__");
        validate_path(
            cache_directory
                .to_str()
                .ok_or("host cache path must be ASCII")?,
        )?;
        let mut caches = Vec::new();
        for (relative, spec) in install_cache_specs()? {
            let path = Path::new(&self.stdlib).join(relative);
            validate_path(path.to_str().ok_or("host cache path must be ASCII")?)?;
            caches.push((path, spec));
        }
        let ancestry = Path::new(&self.stdlib).components().count();
        // The source snapshot has 100 directories plus this one cache owner.
        // The legacy library/six-source verifier retains 9P+12 descriptors;
        // the snapshot adds P+100 directories and three cache descriptors.
        if sources.directories.len() + ancestry > MAX_SNAPSHOT_DIRECTORY_OWNERS {
            return Err("host source snapshot directory owners exceed 256".into());
        }
        let retained = ancestry
            .checked_mul(10)
            .and_then(|count| count.checked_add(115))
            .ok_or("install-only host retained owner count overflow")?;
        if retained > MAX_INSTALL_RETAINED_OWNERS {
            return Err("install-only host retained owners exceed 763".into());
        }
        Ok(InstallSourceSnapshotLayout {
            sources,
            cache_directory,
            caches,
        })
    }

    // The new cache prerequisite already checked both startup directories.
    // Keep the old verifier unchanged so its historical syscall order and
    // reject-all-cache contract remain available to every older profile.
    fn verify_install_startup(&self, image: InstallImage) -> Result<VerifiedHost, String> {
        let mut directories = open_directories(Path::new(&self.stdlib))?;
        directories.append(&mut open_directories(
            &Path::new(&self.stdlib).join("encodings"),
        )?);
        let (size, sha256) = image.identity();
        let (library, mut library_dirs) = verified_file(Path::new(&self.library), size, sha256)?;
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

    fn source_snapshot_layout_from(
        &self,
        specs: BTreeMap<String, ResourceSpec>,
        source_count: usize,
        source_bytes: u64,
        directory_count: usize,
    ) -> Result<SourceSnapshotLayout, String> {
        if specs.len() != source_count {
            return Err("host source snapshot inventory count differs from pins".into());
        }
        validate_resource_paths(specs.keys())
            .map_err(|error| format!("invalid host source snapshot path: {error}"))?;
        let stdlib = Path::new(&self.stdlib);
        let mut files = Vec::with_capacity(specs.len());
        let mut directories = BTreeSet::from([stdlib.to_owned()]);
        let mut encodings = BTreeSet::new();
        let mut total = 0u64;
        for (key, mut spec) in specs {
            let relative = key
                .strip_prefix("stdlib/")
                .ok_or("host source snapshot is outside stdlib")?;
            if !relative.ends_with(".py")
                || spec.size > super::imports::MAX_REPLY as u64
                || spec.sha256.len() != 64
                || !spec
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("invalid host source snapshot metadata".into());
            }
            total = total
                .checked_add(spec.size)
                .ok_or("host source snapshot byte total overflow")?;
            if total > source_bytes {
                return Err("host source snapshot exceeds its pinned byte total".into());
            }
            // Archive compression describes different storage. Host files are
            // raw source bytes with the same exact size/hash identity.
            spec.compression = Compression::Stored;
            let source = stdlib.join(relative);
            validate_path(source.to_str().ok_or("host source path must be ASCII")?)?;
            let mut directory = source.parent().ok_or("host source has no parent")?;
            loop {
                let cache = directory.join("__pycache__");
                validate_path(cache.to_str().ok_or("host cache path must be ASCII")?)?;
                directories.insert(directory.to_owned());
                if directory == stdlib {
                    break;
                }
                directory = directory.parent().ok_or("host source escaped stdlib")?;
            }
            if let Some(name) = relative.strip_prefix("encodings/") {
                if name.contains('/') {
                    return Err("host startup encodings inventory must contain only files".into());
                }
                encodings.insert(name.into());
            }
            files.push((key, source, spec));
        }
        if total != source_bytes || directories.len() != directory_count {
            return Err("host source snapshot layout differs from the pinned projection".into());
        }
        let owner_count = directories.len() + stdlib.components().count() - 1;
        if owner_count > MAX_SNAPSHOT_DIRECTORY_OWNERS {
            return Err("host source snapshot directory owners exceed 256".into());
        }
        // Before the archive finder exists, host startup can consult codecs and
        // encodings. Extension/sourceless/package shadows must not win there.
        let mut startup_shadows = BTreeSet::new();
        for name in ["codecs", "encodings"] {
            for suffix in [
                ".pyc",
                ".pyo",
                ".cpython-313-aarch64-linux-gnu.so",
                ".abi3.so",
                ".so",
            ] {
                startup_shadows.insert(stdlib.join(format!("{name}{suffix}")));
            }
        }
        startup_shadows.insert(stdlib.join("codecs"));
        startup_shadows.insert(stdlib.join("encodings.py"));
        for path in &startup_shadows {
            validate_path(path.to_str().ok_or("host startup path must be ASCII")?)?;
        }
        Ok(SourceSnapshotLayout {
            files,
            directories,
            encodings,
            startup_shadows,
        })
    }

    fn import_sources<'a>(
        &self,
        pins: &'a BTreeMap<String, ResourceSpec>,
    ) -> Result<ImportSources<'a>, String> {
        if Self::parse(&self.prefix)? != *self {
            return Err("host configuration differs from the fixed installation layout".into());
        }
        if pins.len() > MAX_IMPORT_SOURCES {
            return Err("host supplemental source count exceeds 128".into());
        }
        let startup: Vec<_> = MODULE_SPECS
            .iter()
            .map(|spec| spec.source_path.strip_prefix(SOURCE_PREFIX).unwrap())
            .collect();
        if pins.keys().any(|key| startup.contains(&key.as_str())) {
            return Err("host supplemental sources duplicate a startup source".into());
        }
        // Include startup identities so supplemental files cannot introduce a
        // case alias or file/directory conflict with the already pinned subset.
        validate_resource_paths(
            startup
                .iter()
                .copied()
                .chain(pins.keys().map(String::as_str)),
        )
        .map_err(|error| format!("invalid host supplemental source path: {error}"))?;
        let stdlib = Path::new(&self.stdlib);
        let mut files = Vec::with_capacity(pins.len());
        let mut caches = BTreeSet::new();
        let mut total = 0u64;
        for (relative, spec) in pins {
            if !relative.ends_with(".py")
                || spec.compression != Compression::Stored
                || spec.sha256.len() != 64
                || !spec
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("invalid host supplemental source metadata".into());
            }
            total = total
                .checked_add(spec.size)
                .ok_or("host supplemental source byte count overflow")?;
            if total > MAX_IMPORT_SOURCE_BYTES {
                return Err("host supplemental source bytes exceed 4 MiB".into());
            }
            let source = stdlib.join(relative);
            validate_path(source.to_str().ok_or("host source path must be ASCII")?)?;
            let mut directory = source.parent().ok_or("host source has no parent")?;
            while directory != stdlib {
                let cache = directory.join("__pycache__");
                validate_path(cache.to_str().ok_or("host cache path must be ASCII")?)?;
                caches.insert(cache);
                directory = directory.parent().ok_or("host source escaped stdlib")?;
            }
            files.push((source, spec));
        }
        // verify() checks these two locations before any startup file hashing.
        caches.remove(&stdlib.join("encodings/__pycache__"));
        Ok(ImportSources { files, caches })
    }
}

fn install_source_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let pins: serde_json::Value =
        serde_json::from_slice(INSTALL_SOURCE_PINS).map_err(|error| error.to_string())?;
    install_source_specs_from(&pins)
}

fn install_source_specs_from(
    pins: &serde_json::Value,
) -> Result<BTreeMap<String, ResourceSpec>, String> {
    if pins["schema_version"] != 0
        || pins["artifact_sha256"] != super::bundle::INSTALL_ONLY_SHA256
        || pins["artifact_size"] != 57_626_877u64
        || pins["paired_full_artifact_sha256"] != super::bundle::FULL_SHA256
        || pins["paired_full_source_inventory_sha256"]
            != glue_format::digest(super::import_profile::SOURCE_PINS)
        || pins["stock_tar_mtime"] != 1_704_067_200u64
    {
        return Err("install-only source inventory differs from pinned PBS inputs".into());
    }
    let files = pins["files"]
        .as_object()
        .ok_or("missing install-only host source inventory")?;
    if files.len() != INSTALL_SNAPSHOT_SOURCE_COUNT {
        return Err("install-only source inventory count differs from pins".into());
    }
    let full = super::import_profile::source_specs()?;
    let mut specs = BTreeMap::new();
    let mut total = 0u64;
    for (relative, value) in files {
        let key = format!("stdlib/{relative}");
        let source = full
            .get(&key)
            .ok_or("install-only source is outside the full PBS projection")?;
        if !relative.ends_with(".py")
            || value["size"] != source.size
            || value["sha256"] != source.sha256
        {
            return Err("install-only source identity differs from full PBS source".into());
        }
        total = total
            .checked_add(source.size)
            .ok_or("install-only source byte count overflow")?;
        let mut spec = source.clone();
        spec.compression = Compression::Stored;
        specs.insert(key, spec);
    }
    let mut tests = 0usize;
    let mut idle_tests = 0usize;
    for key in full.keys().filter(|key| !specs.contains_key(*key)) {
        if key.starts_with("stdlib/test/") {
            tests += 1;
        } else if key.starts_with("stdlib/idlelib/") {
            idle_tests += 1;
        } else {
            return Err("install-only source omission is outside pinned test packages".into());
        }
    }
    if total != INSTALL_SNAPSHOT_SOURCE_BYTES || tests != 1072 || idle_tests != 65 {
        return Err("install-only source projection differs from pins".into());
    }
    Ok(specs)
}

fn install_cache_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let pins: serde_json::Value =
        serde_json::from_slice(INSTALL_CACHE_PINS).map_err(|error| error.to_string())?;
    install_cache_specs_from(&pins)
}

fn install_cache_specs_from(
    pins: &serde_json::Value,
) -> Result<BTreeMap<String, ResourceSpec>, String> {
    if pins["schema_version"] != 0
        || pins["artifact_sha256"] != super::bundle::INSTALL_ONLY_SHA256
        || pins["artifact_size"] != 57_626_877u64
        || pins["source_inventory_sha256"] != glue_format::digest(INSTALL_SOURCE_PINS)
        || pins["stock_tar_mtime"] != 1_704_067_200u64
        || pins["bytecode_source_mtime"] != 1_791_559_484u64
    {
        return Err("install-only startup cache inventory differs from pinned PBS input".into());
    }
    let files = pins["files"]
        .as_object()
        .ok_or("missing install-only startup cache inventory")?;
    let expected: BTreeSet<_> = INSTALL_CACHE_NAMES
        .iter()
        .map(|name| format!("encodings/__pycache__/{name}"))
        .collect();
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err("install-only startup cache names differ from pins".into());
    }
    let mut specs = BTreeMap::new();
    let mut total = 0u64;
    for (key, value) in files {
        let size = value["size"]
            .as_u64()
            .ok_or("missing install-only startup cache size")?;
        let sha256 = value["sha256"]
            .as_str()
            .ok_or("missing install-only startup cache hash")?;
        if size == 0
            || size > super::imports::MAX_REPLY as u64
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid install-only startup cache metadata".into());
        }
        total = total
            .checked_add(size)
            .ok_or("install-only startup cache byte count overflow")?;
        specs.insert(
            key.clone(),
            ResourceSpec {
                size,
                sha256: sha256.into(),
                compression: Compression::Stored,
            },
        );
    }
    if total != INSTALL_STARTUP_CACHE_BYTES {
        return Err("install-only startup cache byte total differs from pins".into());
    }
    Ok(specs)
}

fn install_snapshot_prerequisites(
    layout: &InstallSourceSnapshotLayout,
    stdlib: &Path,
) -> Result<(Vec<File>, Vec<File>), String> {
    let mut paths = layout.sources.directories.clone();
    paths.insert(layout.cache_directory.clone());
    let directories = snapshot_directories(&paths)?;
    for directory in &layout.sources.directories {
        let cache = directory.join("__pycache__");
        if cache != layout.cache_directory {
            require_cache_absent(&cache)?;
        }
    }
    require_snapshot_startup_with_cache(&layout.sources, stdlib, Some(&layout.cache_directory))?;
    require_closed_startup_caches(layout)?;
    let mut caches = Vec::with_capacity(layout.caches.len());
    for (path, spec) in &layout.caches {
        // Their complete ancestor chains are already held by the deduplicated
        // directory owners. Keep the cache descriptor without duplicating them.
        let file = open_checked(path, false)?;
        let (file, _) = verify_opened_file(path, file, Vec::new(), spec.size, &spec.sha256)?;
        caches.push(file);
    }
    Ok((directories, caches))
}

fn require_closed_startup_caches(layout: &InstallSourceSnapshotLayout) -> Result<(), String> {
    let expected: BTreeSet<_> = layout
        .caches
        .iter()
        .map(|(path, _)| path.file_name().unwrap().to_owned())
        .collect();
    let entries = fs::read_dir(&layout.cache_directory)
        .map_err(|error| format!("list host startup caches: {error}"))?;
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("list host startup caches: {error}"))?;
        let name = entry.file_name();
        if !expected.contains(&name) || !seen.insert(name) {
            return Err(format!(
                "host startup cache entry is outside pinned caches: {}",
                entry.path().display()
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("inspect host startup cache entry: {error}"))?;
        require_kind(&entry.path(), &metadata, false)?;
    }
    if seen != expected {
        return Err("host startup cache inventory differs from pinned caches".into());
    }
    Ok(())
}

fn snapshot_prerequisites(
    layout: &SourceSnapshotLayout,
    stdlib: &Path,
) -> Result<Vec<File>, String> {
    let directories = snapshot_directories(&layout.directories)?;
    for directory in &layout.directories {
        require_cache_absent(&directory.join("__pycache__"))?;
    }
    require_snapshot_startup(layout, stdlib)?;
    Ok(directories)
}

fn snapshot_directories(paths: &BTreeSet<PathBuf>) -> Result<Vec<File>, String> {
    let mut owners = BTreeMap::new();
    for path in paths {
        let mut current = PathBuf::from("/");
        if !owners.contains_key(&current) {
            owners.insert(current.clone(), open_checked(&current, true)?);
        }
        for component in path.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                if !owners.contains_key(&current) {
                    owners.insert(current.clone(), open_checked(&current, true)?);
                }
            }
        }
    }
    Ok(owners.into_values().collect())
}

fn require_snapshot_startup(layout: &SourceSnapshotLayout, stdlib: &Path) -> Result<(), String> {
    require_snapshot_startup_with_cache(layout, stdlib, None)
}

fn require_snapshot_startup_with_cache(
    layout: &SourceSnapshotLayout,
    stdlib: &Path,
    cache_directory: Option<&Path>,
) -> Result<(), String> {
    for path in &layout.startup_shadows {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    "host startup source shadow is unsupported: {}",
                    path.display()
                ));
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            Err(error) => {
                return Err(format!(
                    "inspect host startup shadow {}: {error}",
                    path.display()
                ));
            }
        }
    }
    let directory = stdlib.join("encodings");
    let entries = fs::read_dir(&directory).map_err(|error| {
        format!(
            "list host startup encodings {}: {error}",
            directory.display()
        )
    })?;
    let mut expected = layout.encodings.clone();
    if cache_directory.is_some() {
        expected.insert("__pycache__".into());
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("list host startup encodings: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "host startup encodings name must be ASCII")?;
        let directory = cache_directory.is_some() && name == "__pycache__";
        if !expected.contains(&name) || !seen.insert(name) {
            return Err(format!(
                "host startup encodings entry is outside pinned sources: {}",
                entry.path().display()
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("inspect host startup encodings entry: {error}"))?;
        require_kind(&entry.path(), &metadata, directory)?;
    }
    if seen != expected {
        return Err("host startup encodings inventory differs from pinned sources".into());
    }
    Ok(())
}

fn snapshot_sources(
    sources: &[(String, PathBuf, ResourceSpec)],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    for (key, path, spec) in sources {
        if spec.size > super::imports::MAX_REPLY as u64 {
            return Err("host source snapshot file exceeds its byte bound".into());
        }
        // Every ancestor was opened without following symlinks before cache
        // admission. Recheck the source's path/open/path identity itself here.
        let mut file = open_checked(path, false)?;
        if file.metadata().map_err(|error| error.to_string())?.len() != spec.size {
            return Err(format!("host file size mismatch: {}", path.display()));
        }
        let maximum = spec
            .size
            .checked_add(1)
            .ok_or("host source size overflow")?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(spec.size).map_err(|_| "host source size exceeds address space")?,
        );
        (&mut file)
            .take(maximum)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read host source snapshot {}: {error}", path.display()))?;
        if bytes.len() as u64 != spec.size || glue_format::digest(&bytes) != spec.sha256 {
            return Err(format!("host file identity mismatch: {}", path.display()));
        }
        if file.metadata().map_err(|error| error.to_string())?.len() != spec.size {
            return Err(format!(
                "host file size changed while reading: {}",
                path.display()
            ));
        }
        files.insert(key.clone(), bytes);
        // This descriptor is deliberately absent from SourceSnapshot owners.
        // The next source opens only after this File has been dropped.
    }
    Ok(files)
}

fn verify_import_sources(imports: &ImportSources<'_>) -> Result<(Vec<File>, Vec<File>), String> {
    let mut directories = Vec::new();
    // Guard every cache lookup with retained no-follow directory descriptors.
    // Complete cache prerequisites before hashing any supplemental source.
    for cache in &imports.caches {
        directories.append(&mut open_directories(
            cache.parent().ok_or("host cache has no parent")?,
        )?);
        require_cache_absent(cache)?;
    }
    let mut files = Vec::with_capacity(imports.files.len());
    for (path, spec) in &imports.files {
        let (file, mut source_directories) = verified_file(path, spec.size, &spec.sha256)?;
        files.push(file);
        directories.append(&mut source_directories);
    }
    Ok((files, directories))
}

pub(super) fn require_cache_absent(path: &Path) -> Result<(), String> {
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

pub(super) fn validate_path(path: &str) -> Result<(), String> {
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

pub(super) fn open_directories(path: &Path) -> Result<Vec<File>, String> {
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

pub(super) fn verified_file(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(File, Vec<File>), String> {
    let directories = open_directories(path.parent().ok_or("host file has no parent")?)?;
    let file = open_checked(path, false)?;
    verify_opened_file(path, file, directories, expected_size, expected_sha256)
}

pub(super) fn verified_bounded_file(
    path: &Path,
    maximum: u64,
    expected_sha256: &str,
) -> Result<(File, Vec<File>), String> {
    let directories = open_directories(path.parent().ok_or("host file has no parent")?)?;
    let file = open_checked(path, false)?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if size == 0 || size > maximum {
        return Err(format!(
            "host image size exceeds its bound: {}",
            path.display()
        ));
    }
    verify_opened_file(path, file, directories, size, expected_sha256)
}

fn verify_opened_file(
    path: &Path,
    mut file: File,
    directories: Vec<File>,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(File, Vec<File>), String> {
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

        fn host_source(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join("lib/python3.13").join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            path
        }

        fn config(&self) -> Config {
            Config::parse(self.0.to_str().unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn import_pin(bytes: &[u8]) -> ResourceSpec {
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: glue_format::digest(bytes),
            compression: Compression::Stored,
        }
    }

    fn import_pins(relative: &str, bytes: &[u8]) -> BTreeMap<String, ResourceSpec> {
        BTreeMap::from([(relative.into(), import_pin(bytes))])
    }

    fn snapshot_fixture(fixture: &Fixture) -> SourceSnapshotLayout {
        let stdlib = fixture.0.join("lib/python3.13");
        let files = [
            ("encodings/__init__.py", b"startup source\n".as_slice()),
            ("codecs.py", b"codec source\n".as_slice()),
            ("test/nested/value.py", b"answer = 42\n".as_slice()),
            ("empty.py", b"".as_slice()),
        ]
        .into_iter()
        .map(|(relative, bytes)| {
            (
                format!("stdlib/{relative}"),
                fixture.host_source(relative, bytes),
                import_pin(bytes),
            )
        })
        .collect();
        SourceSnapshotLayout {
            files,
            directories: BTreeSet::from([
                stdlib.clone(),
                stdlib.join("encodings"),
                stdlib.join("test"),
                stdlib.join("test/nested"),
            ]),
            encodings: BTreeSet::from(["__init__.py".into()]),
            startup_shadows: fixture
                .config()
                .source_snapshot_layout()
                .unwrap()
                .startup_shadows,
        }
    }

    fn install_snapshot_fixture(fixture: &Fixture) -> InstallSourceSnapshotLayout {
        let sources = snapshot_fixture(fixture);
        let cache_directory = Path::new(&fixture.config().stdlib).join("encodings/__pycache__");
        fs::create_dir(&cache_directory).unwrap();
        let caches = INSTALL_CACHE_NAMES
            .iter()
            .map(|name| {
                let bytes = format!("verified startup cache {name}\n").into_bytes();
                let path = cache_directory.join(name);
                fs::write(&path, &bytes).unwrap();
                (path, import_pin(&bytes))
            })
            .collect();
        InstallSourceSnapshotLayout {
            sources,
            cache_directory,
            caches,
        }
    }

    #[test]
    fn install_snapshot_layout_pins_the_complete_projection_and_stock_caches() {
        let config = Config::parse("/absent install-only Python").unwrap();
        config.validate_install_source_snapshot_layout().unwrap();
        let layout = config.install_source_snapshot_layout().unwrap();
        assert_eq!(layout.sources.files.len(), 1037);
        assert_eq!(layout.sources.directories.len(), 100);
        assert_eq!(layout.sources.encodings.len(), 122);
        assert_eq!(
            layout
                .sources
                .files
                .iter()
                .map(|(_, _, spec)| spec.size)
                .sum::<u64>(),
            15_894_268
        );
        assert!(layout.sources.files.iter().all(|(key, _, spec)| {
            !key.starts_with("stdlib/test/") && spec.compression == Compression::Stored
        }));
        assert!(layout.sources.files.iter().any(|(key, _, _)| {
            key == "stdlib/site-packages/pip/_vendor/urllib3/contrib/emscripten/fetch.py"
        }));
        assert_eq!(layout.caches.len(), 3);
        assert_eq!(
            layout.caches.iter().map(|(_, spec)| spec.size).sum::<u64>(),
            21_157
        );
        assert!(layout.caches.iter().all(|(path, spec)| {
            path.parent() == Some(layout.cache_directory.as_path())
                && spec.compression == Compression::Stored
        }));
        assert!(!Path::new(&config.prefix).exists());
        let mut changed = config;
        changed.library.push('x');
        assert!(
            changed
                .verify_install_source_snapshot()
                .unwrap_err()
                .contains("fixed installation layout")
        );
    }

    #[test]
    fn install_snapshot_bounds_total_leases_and_all_expanded_paths_before_io() {
        let within_budget = Config::parse(&"/a".repeat(61)).unwrap();
        within_budget
            .validate_install_source_snapshot_layout()
            .unwrap();
        let over_budget = Config::parse(&"/a".repeat(62)).unwrap();
        assert_eq!(
            over_budget.verify_install_source_snapshot().unwrap_err(),
            "install-only host retained owners exceed 763"
        );
        // The install projection is smaller, but a 256-distinct-directory cap
        // alone would permit more than a thousand duplicated startup leases.
        let excessive_directories = Config::parse(&"/a".repeat(154)).unwrap();
        assert_eq!(
            excessive_directories
                .verify_install_source_snapshot()
                .unwrap_err(),
            "host source snapshot directory owners exceed 256"
        );
        let long = Config::parse(&format!(
            "/{}",
            "a".repeat(MAX_PATH_BYTES - LIBRARY_SUFFIX.len() - 1)
        ))
        .unwrap();
        assert!(
            long.verify_install_source_snapshot()
                .unwrap_err()
                .starts_with("host paths must be canonical")
        );
        assert!(
            over_budget
                .import_sources(&import_pins("source.py", b"source"))
                .is_ok()
        );
    }

    #[test]
    fn stripped_snapshot_reuses_bounds_without_accepting_configuration_drift() {
        let missing = Config::parse("/absent stripped-only Python").unwrap();
        missing.validate_install_source_snapshot_layout().unwrap();
        let mut drifted = missing;
        drifted.library.push('x');
        assert!(
            drifted
                .verify_stripped_install_source_snapshot()
                .unwrap_err()
                .contains("fixed installation layout")
        );
        let over_budget = Config::parse(&"/a".repeat(62)).unwrap();
        assert_eq!(
            over_budget
                .verify_stripped_install_source_snapshot()
                .unwrap_err(),
            "install-only host retained owners exceed 763"
        );
        let excessive_directories = Config::parse(&"/a".repeat(154)).unwrap();
        assert_eq!(
            excessive_directories
                .verify_stripped_install_source_snapshot()
                .unwrap_err(),
            "host source snapshot directory owners exceed 256"
        );
        assert_eq!(
            InstallImage::Unstripped.identity(),
            (LIBRARY_SIZE, RUNTIME_LIBRARY_SHA256)
        );
        assert_eq!(
            InstallImage::Stripped.identity(),
            (
                crate::stripped_host::LIBRARY_SIZE,
                crate::stripped_host::LIBRARY_SHA256
            )
        );
        assert_ne!(
            InstallImage::Unstripped.identity(),
            InstallImage::Stripped.identity()
        );
    }

    #[test]
    fn install_snapshot_metadata_rejects_pin_drift_before_any_host_access() {
        let sources: serde_json::Value = serde_json::from_slice(INSTALL_SOURCE_PINS).unwrap();
        let caches: serde_json::Value = serde_json::from_slice(INSTALL_CACHE_PINS).unwrap();
        for field in [
            "schema_version",
            "artifact_sha256",
            "paired_full_source_inventory_sha256",
        ] {
            let mut changed = sources.clone();
            changed[field] = serde_json::json!("changed");
            assert!(install_source_specs_from(&changed).is_err());
        }
        let mut changed = sources;
        changed["files"]["asyncio/taskgroups.py"]["sha256"] = serde_json::json!("f".repeat(64));
        assert!(
            install_source_specs_from(&changed)
                .unwrap_err()
                .contains("identity differs")
        );
        for field in [
            "schema_version",
            "artifact_sha256",
            "source_inventory_sha256",
            "stock_tar_mtime",
            "bytecode_source_mtime",
        ] {
            let mut changed = caches.clone();
            changed[field] = serde_json::json!("changed");
            assert!(install_cache_specs_from(&changed).is_err());
        }
        let mut changed = caches.clone();
        changed["files"]["encodings/__pycache__/__init__.cpython-313.pyc"]["sha256"] =
            serde_json::json!("not a hash");
        assert!(
            install_cache_specs_from(&changed)
                .unwrap_err()
                .contains("invalid")
        );
        let mut changed = caches;
        let files = changed["files"].as_object_mut().unwrap();
        let entry = files
            .remove("encodings/__pycache__/utf_8.cpython-313.pyc")
            .unwrap();
        files.insert(
            "encodings/__pycache__/../utf_8.cpython-313.pyc".into(),
            entry,
        );
        assert!(
            install_cache_specs_from(&changed)
                .unwrap_err()
                .contains("names differ")
        );
    }

    #[test]
    fn install_snapshot_verifies_closed_caches_keeps_rewound_files_and_deduplicates_owners() {
        let fixture = Fixture::new();
        let layout = install_snapshot_fixture(&fixture);
        let (directories, mut caches) =
            install_snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib)).unwrap();
        assert_eq!(
            directories.len(),
            Path::new(&fixture.config().stdlib).components().count() + 4
        );
        assert_eq!(caches.len(), 3);
        for ((path, spec), file) in layout.caches.iter().zip(&mut caches) {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(glue_format::digest(&bytes), spec.sha256);
            assert_eq!(bytes.len() as u64, spec.size);
            fs::remove_file(path).unwrap();
        }
        // Retained descriptors still own the verified files after unlinking.
        for file in &mut caches {
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut byte = [0];
            assert_eq!(file.read(&mut byte).unwrap(), 1);
        }
    }

    #[test]
    fn install_snapshot_rejects_missing_changed_truncated_and_extra_caches() {
        for mode in 0..4 {
            let fixture = Fixture::new();
            let layout = install_snapshot_fixture(&fixture);
            let path = &layout.caches[0].0;
            match mode {
                0 => fs::remove_file(path).unwrap(),
                1 => {
                    let mut bytes = fs::read(path).unwrap();
                    bytes[0] ^= 1;
                    fs::write(path, bytes).unwrap();
                }
                2 => fs::write(path, b"short").unwrap(),
                _ => fs::write(
                    layout.cache_directory.join("extra.cpython-313.pyc"),
                    b"extra",
                )
                .unwrap(),
            }
            let error =
                install_snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib))
                    .unwrap_err();
            assert!(
                error.contains(match mode {
                    0 => "cache inventory differs",
                    1 => "identity mismatch",
                    2 => "size mismatch",
                    _ => "outside pinned caches",
                }),
                "{mode}: {error}"
            );
            assert!(!Path::new(&fixture.config().library).exists());
        }
    }

    #[test]
    fn install_snapshot_checks_all_derived_caches_before_missing_library_or_sources() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let layout = config.install_source_snapshot_layout().unwrap();
        let mut directories = layout.sources.directories.clone();
        directories.insert(layout.cache_directory);
        for directory in &directories {
            fs::create_dir_all(directory).unwrap();
        }
        let cache = Path::new(&config.stdlib).join("site-packages/pip/_vendor/idna/__pycache__");
        fs::create_dir(&cache).unwrap();
        assert_eq!(
            config.verify_install_source_snapshot().unwrap_err(),
            format!(
                "host startup bytecode cache is unsupported: {}",
                cache.display()
            )
        );
        assert!(!Path::new(&config.library).exists());
    }

    #[test]
    fn install_snapshot_keeps_full_host_cache_rejection_and_excludes_other_startup_shadows() {
        for relative in [
            "codecs.pyc",
            "encodings.py",
            "encodings/unreviewed.py",
            "encodings/__init__.so",
        ] {
            let fixture = Fixture::new();
            let layout = install_snapshot_fixture(&fixture);
            fixture.host_source(relative, b"unreviewed startup input");
            let error =
                install_snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib))
                    .unwrap_err();
            assert!(
                error.contains("shadow is unsupported") || error.contains("outside pinned sources"),
                "{relative}: {error}"
            );
        }
        let fixture = Fixture::new();
        let layout = install_snapshot_fixture(&fixture);
        assert!(
            fixture
                .config()
                .verify()
                .unwrap_err()
                .contains("bytecode cache is unsupported")
        );
        assert!(
            snapshot_prerequisites(&layout.sources, Path::new(&fixture.config().stdlib))
                .unwrap_err()
                .contains("bytecode cache is unsupported")
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_snapshot_rejects_cache_directory_file_symlinks_and_nonregular_entries() {
        use std::os::unix::fs::symlink;
        for mode in 0..4 {
            let fixture = Fixture::new();
            let layout = install_snapshot_fixture(&fixture);
            match mode {
                0 => {
                    let real = fixture.0.join("real-cache");
                    fs::rename(&layout.cache_directory, &real).unwrap();
                    symlink(real, &layout.cache_directory).unwrap();
                }
                1 => {
                    fs::remove_file(&layout.caches[0].0).unwrap();
                    symlink(
                        fixture.file("real-cache.pyc", b"cache"),
                        &layout.caches[0].0,
                    )
                    .unwrap();
                }
                2 => {
                    fs::remove_file(&layout.caches[0].0).unwrap();
                    fs::create_dir(&layout.caches[0].0).unwrap();
                }
                _ => {
                    fs::remove_dir_all(&layout.cache_directory).unwrap();
                    fs::write(&layout.cache_directory, b"not a directory").unwrap();
                }
            }
            let error =
                install_snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib))
                    .unwrap_err();
            assert!(error.contains("without symlinks"), "{mode}: {error}");
        }
    }

    #[test]
    fn source_snapshot_layout_is_complete_portable_and_bounds_every_expanded_path() {
        let config = Config::parse("/absent source snapshot host").unwrap();
        config.validate_source_snapshot_layout().unwrap();
        let layout = config.source_snapshot_layout().unwrap();
        assert_eq!(layout.files.len(), 2174);
        assert_eq!(layout.directories.len(), 202);
        assert_eq!(
            layout
                .files
                .iter()
                .map(|(_, _, spec)| spec.size)
                .sum::<u64>(),
            39_158_056
        );
        assert!(
            layout
                .files
                .iter()
                .all(|(_, _, spec)| spec.compression == Compression::Stored)
        );
        assert!(
            layout
                .files
                .iter()
                .any(|(key, _, spec)| key.starts_with("stdlib/test/") && spec.size == 0)
        );
        assert!(
            layout.directories.contains(
                &Path::new(&config.stdlib)
                    .join("test/test_importlib/namespace_pkgs/module_and_namespace_package")
            )
        );
        let long = Config::parse(&format!(
            "/{}",
            "a".repeat(MAX_PATH_BYTES - LIBRARY_SUFFIX.len() - 1)
        ))
        .unwrap();
        assert!(
            long.validate_source_snapshot_layout()
                .unwrap_err()
                .starts_with("host paths must be canonical")
        );
        let mut changed = config;
        changed.stdlib.push('x');
        assert!(
            changed
                .validate_source_snapshot_layout()
                .unwrap_err()
                .contains("fixed installation layout")
        );
    }

    #[test]
    fn source_snapshot_copies_owned_bytes_and_closes_individual_source_descriptors() {
        let fixture = Fixture::new();
        let layout = snapshot_fixture(&fixture);
        let owners = snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib)).unwrap();
        let snapshot = snapshot_sources(&layout.files).unwrap();
        assert_eq!(snapshot["stdlib/test/nested/value.py"], b"answer = 42\n");
        assert_eq!(snapshot["stdlib/empty.py"], b"");
        fs::write(
            fixture.0.join("lib/python3.13/test/nested/value.py"),
            b"changed source\n",
        )
        .unwrap();
        fs::remove_file(fixture.0.join("lib/python3.13/empty.py")).unwrap();
        assert_eq!(snapshot["stdlib/test/nested/value.py"], b"answer = 42\n");
        assert_eq!(snapshot["stdlib/empty.py"], b"");
        assert_eq!(
            owners.len(),
            fixture.0.join("lib/python3.13").components().count() + 3
        );
        #[cfg(target_os = "linux")]
        {
            let control = File::open(&layout.files[0].1).unwrap();
            let targets = || {
                fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
                    .collect::<Vec<_>>()
            };
            assert!(targets().contains(&layout.files[0].1));
            drop(control);
            assert!(
                !targets()
                    .iter()
                    .any(|target| layout.files.iter().any(|(_, path, _)| target == path)),
                "snapshot retained a source descriptor"
            );
        }
    }

    #[test]
    fn source_snapshot_full_projection_keeps_only_distinct_directory_owners() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let layout = config.source_snapshot_layout().unwrap();
        for directory in &layout.directories {
            fs::create_dir_all(directory).unwrap();
        }
        let owners = snapshot_directories(&layout.directories).unwrap();
        assert_eq!(
            owners.len(),
            SNAPSHOT_DIRECTORY_COUNT + Path::new(&config.stdlib).components().count() - 1
        );
        // The fixture prefix has few ancestors; retaining one chain per source
        // would instead exhaust a common 1024-descriptor process budget.
        assert!(owners.len() < 256);
    }

    #[test]
    fn source_snapshot_rejects_excessive_prefix_ancestry_before_host_access() {
        let within_budget = Config::parse(&"/a".repeat(52)).unwrap();
        within_budget.validate_source_snapshot_layout().unwrap();
        let over_budget = Config::parse(&"/a".repeat(53)).unwrap();
        assert_eq!(
            over_budget
                .verify_source_snapshot()
                .unwrap_err()
                .to_string(),
            "host source snapshot directory owners exceed 256"
        );
        // This budget applies only to the new snapshot policy. The legacy
        // supplemental-layout validator continues accepting the same prefix.
        assert!(
            over_budget
                .import_sources(&import_pins("source.py", b"source"))
                .is_ok()
        );
    }

    #[test]
    fn source_snapshot_rejects_missing_corrupt_and_truncated_sources() {
        for mode in 0..3 {
            let fixture = Fixture::new();
            let layout = snapshot_fixture(&fixture);
            let _owners =
                snapshot_prerequisites(&layout, Path::new(&fixture.config().stdlib)).unwrap();
            let path = fixture.0.join("lib/python3.13/test/nested/value.py");
            match mode {
                0 => fs::remove_file(&path).unwrap(),
                1 => fs::write(&path, b"answer = 43\n").unwrap(),
                _ => fs::write(&path, b"truncated").unwrap(),
            }
            let error = snapshot_sources(&layout.files).unwrap_err();
            assert!(
                error.contains(match mode {
                    0 => "host path",
                    1 => "identity mismatch",
                    _ => "size mismatch",
                }),
                "{error}"
            );
        }
    }

    #[test]
    fn source_snapshot_checks_unused_deep_caches_before_the_library_or_sources() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let layout = config.source_snapshot_layout().unwrap();
        for directory in &layout.directories {
            fs::create_dir_all(directory).unwrap();
        }
        let cache = Path::new(&config.stdlib)
            .join("test/test_importlib/namespace_pkgs/module_and_namespace_package/__pycache__");
        fs::create_dir(&cache).unwrap();
        let error = config.verify_source_snapshot().unwrap_err();
        assert_eq!(
            error,
            format!(
                "host startup bytecode cache is unsupported: {}",
                cache.display()
            )
        );
        assert!(!Path::new(&config.library).exists());
    }

    #[test]
    fn source_snapshot_excludes_startup_native_sourceless_and_package_shadows() {
        for relative in [
            "codecs",
            "encodings.py",
            "codecs.pyc",
            "encodings.pyc",
            "codecs.so",
            "encodings.abi3.so",
            "codecs.cpython-313-aarch64-linux-gnu.so",
            "encodings/utf_8.pyc",
            "encodings/__init__.so",
            "encodings/unpinned.py",
            "encodings/extra-directory",
        ] {
            let fixture = Fixture::new();
            let layout = snapshot_fixture(&fixture);
            let stdlib = fixture.0.join("lib/python3.13");
            let path = stdlib.join(relative);
            if relative == "codecs" || relative.ends_with("extra-directory") {
                fs::create_dir(path).unwrap();
            } else {
                fs::write(path, b"unreviewed startup candidate").unwrap();
            }
            let error = snapshot_prerequisites(&layout, &stdlib).unwrap_err();
            assert!(
                error.contains("shadow is unsupported") || error.contains("outside pinned sources"),
                "{relative}: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_snapshot_rejects_source_encoding_cache_and_ancestor_symlinks() {
        use std::os::unix::fs::symlink;
        for mode in 0..4 {
            let fixture = Fixture::new();
            let layout = snapshot_fixture(&fixture);
            let stdlib = fixture.0.join("lib/python3.13");
            match mode {
                0 => {
                    let source = stdlib.join("test/nested/value.py");
                    fs::remove_file(&source).unwrap();
                    symlink(fixture.file("original.py", b"answer = 42\n"), source).unwrap();
                    let _owners = snapshot_prerequisites(&layout, &stdlib).unwrap();
                    assert!(
                        snapshot_sources(&layout.files)
                            .unwrap_err()
                            .contains("without symlinks")
                    );
                }
                1 => {
                    let source = stdlib.join("encodings/__init__.py");
                    fs::remove_file(&source).unwrap();
                    symlink(fixture.file("original.py", b"startup source\n"), source).unwrap();
                    assert!(
                        snapshot_prerequisites(&layout, &stdlib)
                            .unwrap_err()
                            .contains("without symlinks")
                    );
                }
                2 => {
                    symlink(
                        fixture.0.join("absent-cache"),
                        stdlib.join("test/nested/__pycache__"),
                    )
                    .unwrap();
                    assert!(
                        snapshot_prerequisites(&layout, &stdlib)
                            .unwrap_err()
                            .contains("bytecode cache is unsupported")
                    );
                }
                _ => {
                    fs::rename(stdlib.join("test/nested"), fixture.0.join("real-nested")).unwrap();
                    symlink(fixture.0.join("real-nested"), stdlib.join("test/nested")).unwrap();
                    assert!(
                        snapshot_prerequisites(&layout, &stdlib)
                            .unwrap_err()
                            .contains("without symlinks")
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_native_files_check_identity_bounds_and_return_rewound_owners() {
        let fixture = Fixture::new();
        let bytes = b"native image snapshot";
        let path = fixture.file("image.so", bytes);
        let hash = glue_format::digest(bytes);
        let (mut file, parents) = verified_bounded_file(&path, bytes.len() as u64, &hash).unwrap();
        assert!(!parents.is_empty());
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        assert!(verified_bounded_file(&path, bytes.len() as u64 - 1, &hash).is_err());
        assert!(
            verified_bounded_file(&path, bytes.len() as u64, &glue_format::digest(b"other"))
                .is_err()
        );
        let empty = fixture.file("empty.so", b"");
        assert!(verified_bounded_file(&empty, 100, &glue_format::digest(b"")).is_err());
        #[cfg(unix)]
        {
            let alias = fixture.0.join("alias.so");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(verified_bounded_file(&alias, 100, &hash).is_err());
            let directory = fixture.0.join("alias-dir");
            std::os::unix::fs::symlink(&fixture.0, &directory).unwrap();
            assert!(verified_bounded_file(&directory.join("image.so"), 100, &hash).is_err());
        }
    }

    #[test]
    fn rejects_supplemental_metadata_before_host_access() {
        let config = Config::parse("/absent-host-import-prefix").unwrap();
        for relative in [
            "../escape.py",
            "/absolute.py",
            "nested//source.py",
            "nested/./source.py",
            "nested\\source.py",
            "source.pyc",
            "source.PY",
            "NUL.py",
            "sourcé.py",
            "source\0.py",
        ] {
            let error = config
                .verify_imports(&import_pins(relative, b"source"))
                .unwrap_err();
            assert!(
                error.starts_with("invalid host supplemental source"),
                "unexpected error for {relative:?}: {error}"
            );
        }
        for change in 0..4 {
            let mut pins = import_pins("source.py", b"source");
            let spec = pins.get_mut("source.py").unwrap();
            match change {
                0 => spec.compression = Compression::Deflate,
                1 => spec.sha256 = "f".repeat(63),
                2 => spec.sha256 = "F".repeat(64),
                _ => spec.sha256 = "g".repeat(64),
            }
            assert_eq!(
                config.verify_imports(&pins).unwrap_err(),
                "invalid host supplemental source metadata"
            );
        }
    }

    #[test]
    fn rejects_supplemental_startup_duplicates_and_path_aliases() {
        let config = Config::parse("/absent-host-import-prefix").unwrap();
        for spec in MODULE_SPECS {
            let relative = spec.source_path.strip_prefix(SOURCE_PREFIX).unwrap();
            assert_eq!(
                config
                    .verify_imports(&import_pins(relative, b"source"))
                    .unwrap_err(),
                "host supplemental sources duplicate a startup source"
            );
        }
        for pins in [
            import_pins("ENCODINGS/another.py", b"source"),
            import_pins("codecs.py/another.py", b"source"),
            BTreeMap::from([
                ("nested/source.py".into(), import_pin(b"source")),
                ("Nested/another.py".into(), import_pin(b"another")),
            ]),
            BTreeMap::from([
                ("source.py".into(), import_pin(b"source")),
                ("source.py/another.py".into(), import_pin(b"another")),
            ]),
        ] {
            assert!(
                config
                    .verify_imports(&pins)
                    .unwrap_err()
                    .starts_with("invalid host supplemental source path")
            );
        }
    }

    #[test]
    fn bounds_supplemental_count_total_and_expanded_host_paths() {
        let config = Config::parse("/absent-host-import-prefix").unwrap();
        let mut pins: BTreeMap<_, _> = (0..MAX_IMPORT_SOURCES)
            .map(|index| (format!("source_{index}.py"), import_pin(b"")))
            .collect();
        assert!(config.import_sources(&pins).is_ok());
        pins.insert("one_more.py".into(), import_pin(b""));
        assert_eq!(
            config.verify_imports(&pins).unwrap_err(),
            "host supplemental source count exceeds 128"
        );
        let mut pins = import_pins("source.py", b"");
        pins.get_mut("source.py").unwrap().size = MAX_IMPORT_SOURCE_BYTES;
        assert!(config.import_sources(&pins).is_ok());
        pins.insert("one_more.py".into(), import_pin(b"x"));
        assert_eq!(
            config.verify_imports(&pins).unwrap_err(),
            "host supplemental source bytes exceed 4 MiB"
        );
        pins.remove("one_more.py");
        pins.get_mut("source.py").unwrap().size = u64::MAX;
        assert_eq!(
            config.verify_imports(&pins).unwrap_err(),
            "host supplemental source bytes exceed 4 MiB"
        );
        let prefix = format!("/{}", "a".repeat(MAX_PATH_BYTES - LIBRARY_SUFFIX.len() - 1));
        let config = Config::parse(&prefix).unwrap();
        let relative = format!("{}.py", "b".repeat(200));
        assert!(
            config
                .verify_imports(&import_pins(&relative, b""))
                .unwrap_err()
                .starts_with("host paths must be canonical")
        );
        // The source can fit while its longer __pycache__ sibling does not.
        assert!(config.stdlib.len() + "/d/a.py".len() <= MAX_PATH_BYTES);
        assert!(
            config
                .verify_imports(&import_pins("d/a.py", b""))
                .unwrap_err()
                .starts_with("host paths must be canonical")
        );
    }

    #[test]
    fn verifies_nested_supplemental_source_and_retains_rewound_descriptor() {
        let fixture = Fixture::new();
        let bytes = b"reviewed installed source\n";
        fixture.host_source("importlib/resources/_common.py", bytes);
        let pins = import_pins("importlib/resources/_common.py", bytes);
        let config = fixture.config();
        let imports = config.import_sources(&pins).unwrap();
        assert_eq!(
            imports.caches,
            BTreeSet::from([
                fixture.0.join("lib/python3.13/importlib/__pycache__"),
                fixture
                    .0
                    .join("lib/python3.13/importlib/resources/__pycache__"),
            ])
        );
        let (mut files, directories) = verify_import_sources(&imports).unwrap();
        assert!(!directories.is_empty());
        let mut actual = Vec::new();
        files[0].read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn rejects_changed_supplemental_source_size_and_hash() {
        let fixture = Fixture::new();
        fixture.host_source("nested/source.py", b"bad source");
        let config = fixture.config();
        for bytes in [b"different size".as_slice(), b"pin source".as_slice()] {
            let pins = import_pins("nested/source.py", bytes);
            let imports = config.import_sources(&pins).unwrap();
            let error = verify_import_sources(&imports).unwrap_err();
            assert!(error.contains(if bytes.len() == b"bad source".len() {
                "identity mismatch"
            } else {
                "size mismatch"
            }));
        }
    }

    #[test]
    fn rejects_every_nested_cache_before_supplemental_source_access() {
        for relative in ["importlib/__pycache__", "importlib/resources/__pycache__"] {
            let fixture = Fixture::new();
            let stdlib = fixture.0.join("lib/python3.13");
            fs::create_dir_all(stdlib.join("importlib/resources")).unwrap();
            let cache = stdlib.join(relative);
            fs::create_dir(&cache).unwrap();
            let pins = import_pins("importlib/resources/absent.py", b"source");
            let config = fixture.config();
            let imports = config.import_sources(&pins).unwrap();
            assert_eq!(
                verify_import_sources(&imports).unwrap_err(),
                format!(
                    "host startup bytecode cache is unsupported: {}",
                    cache.display()
                )
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_supplemental_source_and_cache_symlinks() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let path = fixture.host_source("nested/source.py", b"source");
        let original = fixture.file("original.py", b"source");
        fs::remove_file(&path).unwrap();
        symlink(&original, &path).unwrap();
        let pins = import_pins("nested/source.py", b"source");
        let config = fixture.config();
        let imports = config.import_sources(&pins).unwrap();
        assert!(
            verify_import_sources(&imports)
                .unwrap_err()
                .contains("without symlinks")
        );
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"source").unwrap();
        let cache = path.parent().unwrap().join("__pycache__");
        symlink(fixture.0.join("absent-cache-target"), &cache).unwrap();
        assert_eq!(
            verify_import_sources(&imports).unwrap_err(),
            format!(
                "host startup bytecode cache is unsupported: {}",
                cache.display()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn checks_supplemental_directory_ancestors_before_cache_queries() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let source = fixture.host_source("original/source.py", b"source");
        fs::create_dir(source.parent().unwrap().join("__pycache__")).unwrap();
        let alias = fixture.0.join("lib/python3.13/alias");
        symlink(source.parent().unwrap(), &alias).unwrap();
        let pins = import_pins("alias/source.py", b"source");
        let config = fixture.config();
        let imports = config.import_sources(&pins).unwrap();
        let error = verify_import_sources(&imports).unwrap_err();
        assert_eq!(
            error,
            format!(
                "host path {} must be a directory without symlinks",
                alias.display()
            )
        );
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
