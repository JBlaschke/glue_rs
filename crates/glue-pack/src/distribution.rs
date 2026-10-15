//! Atomic compact distribution staging shared by language adapters.
use glue_format::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub type Result<T> = std::result::Result<T, Diagnostic>;
#[derive(Clone, Debug)]
pub enum PayloadSource {
    File(PathBuf),
    Bytes { bytes: Vec<u8>, mode: u32 },
    Symlink { target: String },
}
#[derive(Clone, Debug)]
pub struct DistributionInput {
    pub app_id: String,
    pub entrypoint: String,
    pub runtime: RuntimeDescriptor,
    pub launch: RuntimeLaunchSpec,
    pub resources: BTreeMap<String, Vec<u8>>,
    pub payloads: BTreeMap<String, PayloadSource>,
    pub native: NativeInventory,
    pub omissions: BTreeMap<String, String>,
    pub notices: String,
    pub options: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug)]
pub struct DistributionLimits {
    pub archive: ArchiveLimits,
    pub max_input_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_payload_files: usize,
}
impl Default for DistributionLimits {
    fn default() -> Self {
        Self {
            archive: ArchiveLimits::default(),
            max_input_bytes: 1024 * 1024 * 1024,
            max_payload_bytes: 8 * 1024 * 1024 * 1024,
            max_payload_files: 100_000,
        }
    }
}
fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "check the named input and distribution configuration",
    )
}
fn io(path: &Path, e: std::io::Error) -> Diagnostic {
    error(
        DiagnosticCode::MissingInput,
        format!("{}: {e}", path.display()),
    )
}
fn checked_path(path: &str) -> Result<()> {
    validate_payload_path(path).map_err(|e| error(DiagnosticCode::PathEscape, e.to_string()))
}
fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).map_err(|e| io(path, e))?;
    if !metadata.is_file() {
        return Err(error(
            DiagnosticCode::MissingInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > maximum {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            format!("{} exceeds {maximum} bytes", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| io(path, e))?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(path, e))?;
    if bytes.len() as u64 > maximum {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "file grew beyond configured bound",
        ));
    }
    Ok(bytes)
}
#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}
#[cfg(not(unix))]
fn file_mode(_: &fs::Metadata) -> u32 {
    0o644
}
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io(path, e))?;
    }
    let _ = (path, mode);
    Ok(())
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write_new(root: &Path, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    checked_path(path)?;
    let dest = root.join(path);
    fs::create_dir_all(dest.parent().expect("joined path has parent")).map_err(|e| io(&dest, e))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest)
        .map_err(|e| io(&dest, e))?;
    f.write_all(bytes).map_err(|e| io(&dest, e))?;
    f.sync_all().map_err(|e| io(&dest, e))?;
    set_mode(&dest, mode)
}
/// The caller supplies the target-compatible launcher; it is recorded like every executable.
pub fn build(
    input: DistributionInput,
    launcher: &Path,
    output: &Path,
    limits: DistributionLimits,
) -> Result<DistributionBuildReport> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(error(
            DiagnosticCode::OutputExists,
            format!("{} already exists", output.display()),
        ));
    }
    if input.payloads.len() >= limits.max_payload_files {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "too many deployed files",
        ));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| io(parent, e))?;
    let name = output.file_name().ok_or_else(|| {
        error(
            DiagnosticCode::InvalidConfiguration,
            "output needs a directory name",
        )
    })?;
    let output = parent.join(name);
    // Resolve all sources before creating staging, so traversal can never ingest this build.
    let mut input = input;
    if input.payloads.contains_key("glue")
        || input.payloads.keys().any(|p| {
            [
                "app.glue",
                "glue.lock.json",
                "build-report.json",
                "licenses/NOTICE",
            ]
            .contains(&p.as_str())
        })
    {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "input collides with generated distribution files",
        ));
    }
    input
        .payloads
        .insert("glue".into(), PayloadSource::File(launcher.into()));
    validate_resource_paths(input.payloads.keys())
        .map_err(|e| error(DiagnosticCode::PathEscape, e.to_string()))?;
    for p in input.resources.keys() {
        checked_path(p)?;
    }
    let mut total = 0u64;
    for bytes in input.resources.values() {
        total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
            error(
                DiagnosticCode::ResourceLimit,
                "resource byte count overflow",
            )
        })?;
    }
    if total > limits.max_input_bytes {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "archived inputs exceed configured bound",
        ));
    }
    let mut records = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut payload_bytes = 0u64;
    for (path, source) in input.payloads {
        checked_path(&path)?;
        let (bytes, mode, kind) = match source {
            PayloadSource::File(source) => {
                let metadata = fs::symlink_metadata(&source).map_err(|e| io(&source, e))?;
                if metadata.file_type().is_symlink() {
                    return Err(error(
                        DiagnosticCode::PathEscape,
                        format!(
                            "explicit file input {} is a symlink; declare its target",
                            source.display()
                        ),
                    ));
                }
                let canonical = fs::canonicalize(&source).map_err(|e| io(&source, e))?;
                if canonical.starts_with(&output) {
                    return Err(error(
                        DiagnosticCode::PathEscape,
                        "output cannot supply its own input",
                    ));
                }
                (
                    bounded_file(
                        &canonical,
                        limits.max_payload_bytes.saturating_sub(payload_bytes),
                    )?,
                    file_mode(&metadata),
                    PayloadKind::File,
                )
            }
            PayloadSource::Bytes { bytes, mode } => (bytes, mode, PayloadKind::File),
            PayloadSource::Symlink { target } => (
                target.as_bytes().to_vec(),
                0o777,
                PayloadKind::Symlink { target },
            ),
        };
        payload_bytes = payload_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error(DiagnosticCode::ResourceLimit, "payload size overflow"))?;
        if payload_bytes > limits.max_payload_bytes {
            return Err(error(
                DiagnosticCode::ResourceLimit,
                "payload bytes exceed configured bound",
            ));
        }
        records.insert(
            path.clone(),
            PayloadRecord {
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                mode,
                kind,
            },
        );
        sources.insert(path, bytes);
    }
    let manifest = Manifest {
        schema_version: DISTRIBUTION_SCHEMA_VERSION,
        app_id: input.app_id,
        entrypoint: input.entrypoint,
        targets: BTreeMap::new(),
        runtimes: BTreeMap::new(),
        components: BTreeMap::new(),
        native_modules: BTreeMap::new(),
        host_imports: BTreeMap::new(),
        resources: input
            .resources
            .iter()
            .map(|(p, b)| {
                (
                    p.clone(),
                    ResourceSpec {
                        size: b.len() as u64,
                        sha256: digest(b),
                        compression: Compression::Deflate,
                    },
                )
            })
            .collect(),
        distribution: Some(DistributionSpec {
            delivery: DeliveryMode::Compact,
            runtime: input.runtime.clone(),
            payloads: records.clone(),
            native: input.native.clone(),
            launch: input.launch,
        }),
    };
    manifest
        .validate()
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    let archive = write_archive(Cursor::new(Vec::new()), &manifest, &input.resources)
        .map_err(|e| error(DiagnosticCode::ResourceLimit, e.to_string()))?
        .into_inner();
    let mut verified = Archive::open_with_limits(Cursor::new(&archive), limits.archive)
        .map_err(|e| error(DiagnosticCode::ResourceLimit, e.to_string()))?;
    verified
        .verify_all()
        .map_err(|e| error(DiagnosticCode::PayloadIntegrity, e.to_string()))?;
    let mut identities = input.runtime.inputs.clone();
    for (path, bytes) in &input.resources {
        identities.insert(format!("archive:{path}"), InputIdentity::of(bytes));
    }
    for (path, record) in &records {
        identities.insert(
            format!("payload:{path}"),
            InputIdentity {
                size: record.size,
                sha256: record.sha256.clone(),
            },
        );
    }
    let lock = BuildLock {
        revision: 1,
        runtime: input.runtime.clone(),
        inputs: identities,
        transformations: input.native.transformations.clone(),
        options: input.options,
    };
    let lock_bytes = serde_json::to_vec_pretty(&lock)
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    let mut directories = BTreeSet::new();
    for p in records
        .keys()
        .map(String::as_str)
        .chain(["licenses/NOTICE"])
    {
        let mut path = Path::new(p).parent();
        while let Some(p) = path {
            if !p.as_os_str().is_empty() {
                directories.insert(p.to_owned());
            }
            path = p.parent();
        }
    }
    let mut report=DistributionBuildReport { revision:1,runtime:input.runtime,archive:InputIdentity::of(&archive),payloads:records.clone(),native:input.native,
        sizes:SizeAccounting { archive_bytes:archive.len() as u64,archived_uncompressed_bytes:total,payload_bytes:0,deployed_files:records.len() as u64+4,deployed_directories:directories.len() as u64 },
        omissions:input.omissions,limitations:vec!["Compact mode requires immutable deployment storage; hashes do not eliminate mutable-storage check/exec races.".into()] };
    // Account for the report itself, reaching a stable decimal-size representation.
    let fixed_bytes = payload_bytes + lock_bytes.len() as u64 + input.notices.len() as u64;
    let report_bytes = loop {
        let bytes = serde_json::to_vec_pretty(&report)
            .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
        let measured = fixed_bytes + bytes.len() as u64;
        if report.sizes.payload_bytes == measured {
            break bytes;
        }
        report.sizes.payload_bytes = measured;
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stage = loop {
        let candidate = parent.join(format!(
            ".glue-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break Stage(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(&candidate, e)),
        }
    };
    // Regular files first. Links cannot redirect any subsequent writes.
    for (path, record) in &records {
        if matches!(record.kind, PayloadKind::File) {
            write_new(&stage.0, path, &sources[path], record.mode)?;
        }
    }
    write_new(&stage.0, "app.glue", &archive, 0o644)?;
    write_new(&stage.0, "glue.lock.json", &lock_bytes, 0o644)?;
    write_new(&stage.0, "build-report.json", &report_bytes, 0o644)?;
    write_new(&stage.0, "licenses/NOTICE", input.notices.as_bytes(), 0o644)?;
    for (path, record) in &records {
        if let PayloadKind::Symlink { target } = &record.kind {
            let dest = stage.0.join(path);
            fs::create_dir_all(dest.parent().unwrap()).map_err(|e| io(&dest, e))?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &dest).map_err(|e| io(&dest, e))?;
            #[cfg(not(unix))]
            return Err(error(
                DiagnosticCode::UnsupportedCapability,
                "compact symlinks need Unix",
            ));
        }
    }
    rename_exclusive(&stage.0, &output)?;
    Ok(report)
}
/// Atomic directory publication without replacing another builder's output.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
fn rename_exclusive(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let a = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| error(DiagnosticCode::PathEscape, "NUL in staging path"))?;
    let b = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| error(DiagnosticCode::PathEscape, "NUL in output path"))?;
    // SAFETY: CStrings are NUL-terminated and valid throughout this atomic rename;
    // no ownership or pointer is retained by the kernel.
    let status = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::renameatx_np(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_EXCL,
            )
        }
        #[cfg(target_os = "linux")]
        {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            ) as i32
        }
    };
    if status != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(error(
                DiagnosticCode::OutputExists,
                "another output already exists",
            ));
        }
        return Err(io(to, e));
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_exclusive(_: &Path, _: &Path) -> Result<()> {
    Err(error(
        DiagnosticCode::UnsupportedCapability,
        "atomic compact publication requires Linux or macOS",
    ))
}

/// Deterministic safe traversal, called before staging. Exclusions include output and its staging namespace.
pub fn collect_tree(
    root: &Path,
    output: Option<&Path>,
    max_files: usize,
) -> Result<BTreeMap<String, PathBuf>> {
    let root = fs::canonicalize(root).map_err(|e| io(root, e))?;
    if !root.is_dir() {
        return Err(error(
            DiagnosticCode::MissingInput,
            "input root must be a directory",
        ));
    }
    let output = output.map(|p| {
        fs::canonicalize(p).unwrap_or_else(|_| {
            let parent = p
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            fs::canonicalize(parent)
                .unwrap_or_else(|_| parent.to_owned())
                .join(p.file_name().unwrap_or_default())
        })
    });
    let mut result = BTreeMap::new();
    let mut ancestors = BTreeSet::new();
    fn walk(
        root: &Path,
        dir: &Path,
        prefix: &str,
        output: Option<&Path>,
        max: usize,
        ancestors: &mut BTreeSet<PathBuf>,
        result: &mut BTreeMap<String, PathBuf>,
    ) -> Result<()> {
        let canonical = fs::canonicalize(dir).map_err(|e| io(dir, e))?;
        if !canonical.starts_with(root) {
            return Err(error(
                DiagnosticCode::PathEscape,
                format!("{} escapes input root", dir.display()),
            ));
        }
        if !ancestors.insert(canonical.clone()) {
            return Err(error(DiagnosticCode::PathEscape, "directory symlink cycle"));
        }
        let mut entries = fs::read_dir(dir)
            .map_err(|e| io(dir, e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| io(dir, e))?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e
                .file_name()
                .into_string()
                .map_err(|_| error(DiagnosticCode::PathEscape, "non-UTF8 input path"))?;
            if name == ".git"
                || name.starts_with(".glue-stage-")
                || output.is_some_and(|o| e.path() == o)
            {
                continue;
            }
            let logical = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            checked_path(&logical)?;
            let resolved = fs::canonicalize(e.path()).map_err(|err| io(&e.path(), err))?;
            if !resolved.starts_with(root) {
                return Err(error(
                    DiagnosticCode::PathEscape,
                    format!("{logical} escapes input root"),
                ));
            }
            if resolved.is_dir() {
                walk(root, &e.path(), &logical, output, max, ancestors, result)?;
            } else if resolved.is_file() {
                if result.len() >= max {
                    return Err(error(
                        DiagnosticCode::ResourceLimit,
                        "input file count exceeds configured bound",
                    ));
                }
                result.insert(logical, resolved);
            } else {
                return Err(error(
                    DiagnosticCode::UnsupportedCapability,
                    format!("{logical} is not a regular file"),
                ));
            }
        }
        ancestors.remove(&canonical);
        Ok(())
    }
    walk(
        &root,
        &root,
        "",
        output.as_deref(),
        max_files,
        &mut ancestors,
        &mut result,
    )?;
    Ok(result)
}
