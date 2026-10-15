//! Portable, source-only normalization of an already installed Python tree.
//!
//! The adapter reads bounded data. It never starts an interpreter, resolves
//! dependencies, follows generated wrappers or executes an installation hook.

pub mod discovery;
pub mod inventory;

use super::{
    BuildReport, PackError, PackLimits, build_owned, canonical_root, check_limit, input_io,
    io_error, read_manifest, resource_error, resource_file,
};
use glue_format::{
    Compression, MAX_MANIFEST_BYTES, Manifest, ResourcePath, ResourceSpec, RuntimeAbi,
    RuntimeVersion, digest,
};
use glue_runtime_python::packaging;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_FILES: u64 = 1024;
const MAX_APP_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_METADATA: u64 = 64 * 1024;
const MAX_RECORD: u64 = 256 * 1024;
const MAX_SCAN_NODES: u64 = 4096;
const MAX_SCAN_DIRECTORIES: u64 = 1024;
const MAX_SCAN_DEPTH: u64 = 32;

#[derive(Clone, Copy, Debug)]
pub enum PackageInput<'a> {
    SitePackages(&'a Path),
    Venv(&'a Path),
}

#[derive(Clone, Copy, Debug)]
pub struct PythonBuildOptions<'a> {
    pub provider_template: &'a Path,
    pub provider_root: &'a Path,
    pub application: &'a Path,
    pub packages: PackageInput<'a>,
    pub app_id: &'a str,
    pub entry: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonBuildReport {
    pub build: BuildReport,
    pub package_input: String,
    pub distributions: Vec<DistributionReport>,
    pub inputs: Vec<InputIdentity>,
    pub omissions: Vec<Omission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DistributionReport {
    pub name: String,
    pub version: String,
    pub directory: String,
    pub original_record_sha256: String,
    pub original_record_bytes: u64,
    pub retained_files: usize,
}

/// Paths are relative to the named input; provider and application identities
/// use archive resource paths. No machine-specific absolute paths are emitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InputIdentity {
    pub source: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct Omission {
    pub path: String,
    pub reason: String,
}

/// Build using the exact admitted provider declaration and a complete installed
/// package inventory. Inputs must remain stable while being read. Validation
/// and generated-archive verification finish before publication with create_new.
pub fn build(
    options: PythonBuildOptions<'_>,
    output: &Path,
) -> Result<PythonBuildReport, PackError> {
    let template_bytes = read_manifest(options.provider_template, MAX_MANIFEST_BYTES as u64)?;
    let template = Manifest::from_json(&template_bytes).map_err(|source| PackError::Manifest {
        path: options.provider_template.to_owned(),
        source,
    })?;
    let archive_limits = packaging::validate_template(&template).map_err(PackError::Profile)?;
    check_limit(
        "manifest bytes",
        template_bytes.len() as u64,
        archive_limits.max_manifest_bytes,
    )?;

    let mut inputs = vec![identity("template", "manifest.json", &template_bytes)];
    let (package_root, package_input) = match options.packages {
        PackageInput::SitePackages(root) => (canonical_root(root)?, "site_packages"),
        PackageInput::Venv(root) => (venv_packages(root, &mut inputs)?, "venv"),
    };
    let application_root = canonical_root(options.application)?;
    let app_directory = directory_under(&application_root, "app")?;
    let mut scan = ScanBudget::default();
    let app_inventory = scan_tree(&app_directory, &mut scan)?;
    let package_inventory = scan_tree(&package_root, &mut scan)?;
    let mut budget = ApplicationBudget::default();
    let mut resources = BTreeMap::new();
    let mut omissions = BTreeSet::new();

    for (path, size) in app_inventory {
        let key = format!("app/{path}");
        unsupported_path(&path)?;
        if cache_path(&path) {
            omissions.insert(omission(&key, "bytecode_or_cache"));
            continue;
        }
        retained_cache_path(&path)?;
        budget.add(size)?;
        let bytes = read_scanned_input(&app_directory, &path, size, MAX_FILE_BYTES)?;
        inputs.push(identity("application", &key, &bytes));
        resources.insert(key, bytes);
    }

    let RuntimeAbi::Python { version, .. } = &template.runtimes["python"].abi else {
        unreachable!("template admission established the pinned Python runtime")
    };
    let normalized = normalize_packages(&package_root, package_inventory, &mut budget, version)?;
    for (path, bytes) in normalized.files {
        let key = format!("app/python/{path}");
        if resources.insert(key.clone(), bytes).is_some() {
            return Err(PackError::Profile(format!(
                "installed package collides with an explicit application file: {key}"
            )));
        }
    }
    inputs.extend(normalized.inputs);
    omissions.extend(normalized.omissions);
    let application_specs = resources
        .iter()
        .map(|(path, bytes)| (path.clone(), specification(bytes)))
        .collect();
    let manifest = packaging::application_manifest(
        &template,
        options.app_id,
        options.entry,
        application_specs,
    )
    .map_err(PackError::Profile)?;

    // Explicit application files can supply distributions in addition to the
    // installed input. Check their combined owned METADATA before reading any
    // provider resources; full content validation still follows those reads.
    for (path, bytes) in &resources {
        let Some((directory, member)) = path
            .strip_prefix("app/python/")
            .and_then(|relative| relative.split_once('/'))
        else {
            continue;
        };
        if directory.ends_with(".dist-info") && member == "METADATA" {
            check_limit(
                "distribution METADATA bytes",
                bytes.len() as u64,
                MAX_METADATA,
            )?;
            let metadata = std::str::from_utf8(bytes).map_err(|_| {
                PackError::Profile(format!("distribution METADATA is not UTF-8: {path}"))
            })?;
            packaging::validate_requires_python(metadata, version).map_err(|error| {
                PackError::Profile(format!("distribution {directory}: {error}"))
            })?;
        }
    }

    let provider_root = canonical_root(options.provider_root)?;
    let mut total = resources
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum::<u64>();
    let limits = PackLimits {
        archive_limits,
        ..PackLimits::default()
    };
    for (path, spec) in manifest
        .resources
        .iter()
        .filter(|(path, _)| !path.starts_with("app/"))
    {
        check_limit(
            "resource bytes",
            spec.size,
            limits.archive_limits.max_entry_bytes,
        )?;
        total = total.checked_add(spec.size).ok_or(PackError::Allocation)?;
        check_limit("input bytes", total, limits.max_input_bytes)?;
        check_limit(
            "total resource bytes",
            total,
            limits.archive_limits.max_total_uncompressed_bytes,
        )?;
        let bytes = read_input(&provider_root, path, spec.size)?;
        if bytes.len() as u64 != spec.size || digest(&bytes) != spec.sha256 {
            return Err(resource_error(
                path,
                &provider_root.join(path),
                "provider bytes differ from template identity",
            ));
        }
        inputs.push(identity("provider", path, &bytes));
        resources.insert(path.clone(), bytes);
    }
    packaging::validate_application_contents(&manifest, &resources).map_err(PackError::Profile)?;
    inputs.sort_by(|left, right| (&left.source, &left.path).cmp(&(&right.source, &right.path)));
    let build = build_owned(&manifest, resources, output, limits)?;
    Ok(PythonBuildReport {
        build,
        package_input: package_input.into(),
        distributions: normalized.distributions,
        inputs,
        omissions: omissions.into_iter().collect(),
    })
}

fn identity(source: &str, path: &str, bytes: &[u8]) -> InputIdentity {
    InputIdentity {
        source: source.into(),
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn omission(path: &str, reason: &str) -> Omission {
    Omission {
        path: path.into(),
        reason: reason.into(),
    }
}

fn specification(bytes: &[u8]) -> ResourceSpec {
    ResourceSpec {
        size: bytes.len() as u64,
        sha256: digest(bytes),
        compression: Compression::Stored,
    }
}

fn directory_under(root: &Path, relative: &str) -> Result<PathBuf, PackError> {
    ResourcePath::new(relative).map_err(|error| PackError::Profile(error.to_string()))?;
    let mut directory = root.to_owned();
    for component in relative.split('/') {
        directory.push(component);
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|source| io_error("stat input directory", &directory, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(resource_error(
                relative,
                &directory,
                "input directory components must be directories and cannot be symlinks",
            ));
        }
    }
    Ok(directory)
}

fn read_input(root: &Path, relative: &str, maximum: u64) -> Result<Vec<u8>, PackError> {
    let path = resource_file(root, relative)?;
    let metadata =
        fs::metadata(&path).map_err(|source| input_io(relative, &path, "stat input", source))?;
    check_limit("input file bytes", metadata.len(), maximum)?;
    let file =
        File::open(&path).map_err(|source| input_io(relative, &path, "open input", source))?;
    let metadata = file
        .metadata()
        .map_err(|source| input_io(relative, &path, "stat open input", source))?;
    if !metadata.is_file() {
        return Err(resource_error(
            relative,
            &path,
            "open input is not a regular file",
        ));
    }
    check_limit("input file bytes", metadata.len(), maximum)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(metadata.len()).map_err(|_| PackError::Allocation)?)
        .map_err(|_| PackError::Allocation)?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| input_io(relative, &path, "read bounded input", source))?;
    check_limit("input file bytes", bytes.len() as u64, maximum)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(resource_error(
            relative,
            &path,
            "file changed size while being read",
        ));
    }
    Ok(bytes)
}

fn read_scanned_input(
    root: &Path,
    path: &str,
    size: u64,
    maximum: u64,
) -> Result<Vec<u8>, PackError> {
    let bytes = read_input(root, path, maximum)?;
    if bytes.len() as u64 != size {
        return Err(resource_error(
            path,
            &root.join(path),
            "file changed size after inventory scan",
        ));
    }
    Ok(bytes)
}

#[derive(Default)]
struct ScanBudget {
    nodes: u64,
    directories: u64,
}

fn scan_tree(root: &Path, budget: &mut ScanBudget) -> Result<BTreeMap<String, u64>, PackError> {
    let mut files = BTreeMap::new();
    scan_directory(root, "", 0, budget, &mut files)?;
    Ok(files)
}

fn scan_directory(
    root: &Path,
    relative: &str,
    depth: u64,
    budget: &mut ScanBudget,
    files: &mut BTreeMap<String, u64>,
) -> Result<(), PackError> {
    check_limit("input directory depth", depth, MAX_SCAN_DEPTH)?;
    budget.directories += 1;
    check_limit(
        "input directory count",
        budget.directories,
        MAX_SCAN_DIRECTORIES,
    )?;
    let directory = root.join(relative);
    let entries = fs::read_dir(&directory)
        .map_err(|source| io_error("read input directory", &directory, source))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read directory entry", &directory, source))?;
        budget.nodes += 1;
        check_limit("input scan entries", budget.nodes, MAX_SCAN_NODES)?;
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| PackError::Profile("input filenames must be UTF-8".into()))?,
        );
    }
    names.sort();
    for name in names {
        let path = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        ResourcePath::new(&path)
            .map_err(|error| PackError::Profile(format!("invalid input path: {error}")))?;
        let physical = root.join(&path);
        let metadata = fs::symlink_metadata(&physical)
            .map_err(|source| io_error("stat scanned input", &physical, source))?;
        if metadata.file_type().is_symlink() {
            return Err(resource_error(
                &path,
                &physical,
                "symlink input components are forbidden",
            ));
        }
        if metadata.is_dir() {
            unsupported_path(&path)?;
            scan_directory(root, &path, depth + 1, budget, files)?;
        } else if metadata.is_file() {
            files.insert(path, metadata.len());
        } else {
            return Err(resource_error(
                &path,
                &physical,
                "input is not a regular file or directory",
            ));
        }
    }
    Ok(())
}

#[derive(Default)]
struct ApplicationBudget {
    files: u64,
    bytes: u64,
}

impl ApplicationBudget {
    fn add(&mut self, size: u64) -> Result<(), PackError> {
        check_limit("application file bytes", size, MAX_FILE_BYTES)?;
        self.files += 1;
        self.bytes = self.bytes.checked_add(size).ok_or(PackError::Allocation)?;
        check_limit("application files", self.files, MAX_FILES)?;
        check_limit("application bytes", self.bytes, MAX_APP_BYTES)
    }
}

fn cache_path(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".pyc") || path.to_ascii_lowercase().ends_with(".pyo")
}

fn retained_cache_path(path: &str) -> Result<(), PackError> {
    if path
        .split('/')
        .any(|part| part.eq_ignore_ascii_case("__pycache__"))
    {
        return Err(PackError::Profile(format!(
            "non-bytecode files under cache directories are unsupported: {path}"
        )));
    }
    Ok(())
}

fn unsupported_path(path: &str) -> Result<(), PackError> {
    for part in path.split('/') {
        let part = part.to_ascii_lowercase();
        if part.ends_with(".pth")
            || part.ends_with(".egg-info")
            || part.ends_with(".egg-link")
            || part.ends_with(".egg")
        {
            return Err(PackError::Profile(format!(
                "installed path hooks and legacy editable/egg layouts are unsupported: {path}"
            )));
        }
        if [
            ".so", ".dll", ".pyd", ".dylib", ".bundle", ".node", ".exe", ".o", ".a", ".lib",
        ]
        .iter()
        .any(|suffix| part.ends_with(suffix))
            || part.contains(".so.")
        {
            return Err(PackError::Profile(format!(
                "native installed inputs are unsupported: {path}"
            )));
        }
    }
    Ok(())
}

fn venv_packages(root: &Path, inputs: &mut Vec<InputIdentity>) -> Result<PathBuf, PackError> {
    let root = canonical_root(root)?;
    let bytes = read_input(&root, "pyvenv.cfg", MAX_METADATA)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| PackError::Profile("pyvenv.cfg must be UTF-8".into()))?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| PackError::Profile("pyvenv.cfg requires key = value lines".into()))?;
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() || values.insert(key, value.trim().to_owned()).is_some() {
            return Err(PackError::Profile(
                "pyvenv.cfg contains empty or duplicate keys".into(),
            ));
        }
    }
    if values
        .get("include-system-site-packages")
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
        != Some("false")
    {
        return Err(PackError::Profile(
            "venv requires include-system-site-packages = false".into(),
        ));
    }
    let version = values
        .get("version")
        .ok_or_else(|| PackError::Profile("venv configuration is missing version".into()))?;
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts[0] != "3"
        || parts[1] != "13"
        || parts[2].is_empty()
        || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PackError::Profile(
            "venv convenience mode requires conventional Python 3.13.x".into(),
        ));
    }
    if values
        .get("implementation")
        .is_some_and(|value| !value.eq_ignore_ascii_case("cpython"))
        || values
            .get("free-threaded")
            .is_some_and(|value| !value.eq_ignore_ascii_case("false"))
        || values.get("executable").is_some_and(|value| {
            value
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("python3.13t"))
        })
    {
        return Err(PackError::Profile(
            "free-threaded or alternative-interpreter venv layouts are unsupported".into(),
        ));
    }
    // Inspect spelling from the directory inventory rather than looking up
    // "Lib": a case-insensitive builder would otherwise mistake Unix "lib"
    // for the Windows directory. Interpreter entries are never inspected.
    let mut root_entries = 0;
    for entry in fs::read_dir(&root).map_err(|source| io_error("read venv root", &root, source))? {
        root_entries += 1;
        check_limit("venv root entries", root_entries, MAX_SCAN_NODES)?;
        let entry = entry.map_err(|source| io_error("read venv root entry", &root, source))?;
        if entry.file_name() == "Lib" {
            return Err(PackError::Profile(
                "Windows or ambiguous venv layouts are unsupported".into(),
            ));
        }
    }
    let lib = directory_under(&root, "lib")?;
    let mut count = 0;
    for entry in fs::read_dir(&lib).map_err(|source| io_error("read venv lib", &lib, source))? {
        count += 1;
        check_limit("venv lib entries", count, MAX_SCAN_NODES)?;
        let entry = entry.map_err(|source| io_error("read venv lib entry", &lib, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PackError::Profile("venv lib names must be UTF-8".into()))?;
        if name.starts_with("python") && name != "python3.13" {
            return Err(PackError::Profile(
                "ambiguous or free-threaded venv Python layout".into(),
            ));
        }
    }
    inputs.push(identity("venv", "pyvenv.cfg", &bytes));
    directory_under(&root, "lib/python3.13/site-packages")
}

struct NormalizedPackages {
    files: BTreeMap<String, Vec<u8>>,
    distributions: Vec<DistributionReport>,
    inputs: Vec<InputIdentity>,
    omissions: BTreeSet<Omission>,
}

fn metadata_text<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a str, PackError> {
    let bytes = files
        .get(path)
        .ok_or_else(|| PackError::Profile(format!("installed distribution is missing {path}")))?;
    std::str::from_utf8(bytes)
        .map_err(|_| PackError::Profile(format!("installed metadata must be UTF-8: {path}")))
}

fn normalize_packages(
    root: &Path,
    inventory: BTreeMap<String, u64>,
    budget: &mut ApplicationBudget,
    version: &RuntimeVersion,
) -> Result<NormalizedPackages, PackError> {
    let mut files = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut omissions = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for (path, size) in &inventory {
        unsupported_path(path)?;
        if cache_path(path) {
            omissions.insert(omission(path, "bytecode_or_cache"));
            continue;
        }
        retained_cache_path(path)?;
        let components: Vec<_> = path.split('/').collect();
        if components.iter().any(|part| part.ends_with(".dist-info")) {
            if components.len() < 2
                || !components[0].ends_with(".dist-info")
                || components[1..]
                    .iter()
                    .any(|part| part.ends_with(".dist-info"))
            {
                return Err(PackError::Profile(format!(
                    "installed distribution metadata must be a top-level directory: {path}"
                )));
            }
            packaging::folder_identity(components[0]).map_err(PackError::Profile)?;
            directories.insert(components[0].to_owned());
            check_limit("installed distributions", directories.len() as u64, 64)?;
        }
        let maximum = match components.last().copied() {
            Some("RECORD") if components[0].ends_with(".dist-info") => MAX_RECORD,
            Some(
                "METADATA" | "WHEEL" | "entry_points.txt" | "top_level.txt" | "direct_url.json",
            ) if components[0].ends_with(".dist-info") => MAX_METADATA,
            _ => MAX_FILE_BYTES,
        };
        check_limit("installed metadata bytes", *size, maximum)?;
        budget.add(*size)?;
        let bytes = read_scanned_input(root, path, *size, maximum)?;
        inputs.push(identity("packages", path, &bytes));
        files.insert(path.clone(), bytes);
    }
    let mut names = BTreeSet::new();
    let mut ownership = BTreeMap::new();
    let mut distributions = Vec::new();
    for directory in directories {
        let prefix = format!("{directory}/");
        let metadata = metadata_text(&files, &format!("{prefix}METADATA"))?;
        packaging::validate_requires_python(metadata, version)
            .map_err(|error| PackError::Profile(format!("distribution {directory}: {error}")))?;
        let (name, version) = packaging::metadata_identity(metadata).map_err(PackError::Profile)?;
        let (folder_name, folder_version) =
            packaging::folder_identity(&directory).map_err(PackError::Profile)?;
        if name != folder_name || version != folder_version {
            return Err(PackError::Profile(format!(
                "installed distribution Name/Version differs from directory: {directory}"
            )));
        }
        if !names.insert(name.clone()) {
            return Err(PackError::Profile(
                "installed distributions have duplicate normalized Names".into(),
            ));
        }
        validate_wheel(metadata_text(&files, &format!("{prefix}WHEEL"))?)?;
        if let Some(bytes) = files.get(&format!("{prefix}direct_url.json")) {
            validate_direct_url(bytes)?;
        }
        let wrappers = files
            .get(&format!("{prefix}entry_points.txt"))
            .map(|_| {
                metadata_text(&files, &format!("{prefix}entry_points.txt")).and_then(wrapper_names)
            })
            .transpose()?
            .unwrap_or_default();
        let record_path = format!("{prefix}RECORD");
        let original = metadata_text(&files, &record_path)?;
        let original_record_sha256 = digest(original.as_bytes());
        let original_record_bytes = original.len() as u64;
        let rows = packaging::record_rows(original).map_err(PackError::Profile)?;
        let mut retained = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for [path, hash, size] in rows {
            if !seen.insert(path.clone()) {
                return Err(PackError::Profile(
                    "installed RECORD contains duplicate paths".into(),
                ));
            }
            if ownership.insert(path.clone(), directory.clone()).is_some() {
                return Err(PackError::Profile(
                    "installed distributions share RECORD ownership".into(),
                ));
            }
            if path.contains(['\r', '\n']) {
                return Err(PackError::Profile(
                    "installed RECORD paths cannot contain CR or LF".into(),
                ));
            }
            if let Some(wrapper) = path.strip_prefix("../../../bin/") {
                if wrappers.contains(wrapper) {
                    omissions.insert(omission(&path, "generated_entry_point_wrapper"));
                    continue;
                }
            }
            ResourcePath::new(&path).map_err(|error| {
                PackError::Profile(format!("invalid installed RECORD path: {error}"))
            })?;
            let first = path.split('/').next().unwrap();
            if first.ends_with(".dist-info") && first != directory {
                return Err(PackError::Profile(
                    "installed RECORD references another distribution's metadata".into(),
                ));
            }
            unsupported_path(&path)?;
            if cache_path(&path) {
                omissions.insert(omission(&path, "bytecode_or_cache"));
                continue;
            }
            retained_cache_path(&path)?;
            let bytes = files.get(&path).ok_or_else(|| {
                PackError::Profile(format!(
                    "installed RECORD references a missing file: {path}"
                ))
            })?;
            if path == record_path {
                if !hash.is_empty() || !size.is_empty() {
                    return Err(PackError::Profile(
                        "installed RECORD self-entry requires empty hash and size".into(),
                    ));
                }
            } else {
                if !hash.is_empty() && hash != packaging::record_hash(bytes) {
                    return Err(PackError::Profile(format!(
                        "installed RECORD SHA-256 differs for {path}"
                    )));
                }
                if !size.is_empty()
                    && (!size.bytes().all(|byte| byte.is_ascii_digit())
                        || size.parse::<u64>().ok() != Some(bytes.len() as u64))
                {
                    return Err(PackError::Profile(format!(
                        "installed RECORD size differs for {path}"
                    )));
                }
            }
            retained.insert(path);
        }
        if !retained.contains(&record_path) {
            return Err(PackError::Profile(
                "installed RECORD is missing its self-entry".into(),
            ));
        }
        let mut rewritten = String::new();
        for path in &retained {
            let (hash, size) = if path == &record_path {
                (String::new(), String::new())
            } else {
                let bytes = &files[path];
                (packaging::record_hash(bytes), bytes.len().to_string())
            };
            rewritten.push_str(&format!("{},{hash},{size}\n", csv_path(path)));
        }
        check_limit("rewritten RECORD bytes", rewritten.len() as u64, MAX_RECORD)?;
        budget.bytes = budget.bytes - original_record_bytes + rewritten.len() as u64;
        check_limit("application bytes", budget.bytes, MAX_APP_BYTES)?;
        files.insert(record_path, rewritten.into_bytes());
        distributions.push(DistributionReport {
            name,
            version,
            directory,
            original_record_sha256,
            original_record_bytes,
            retained_files: retained.len(),
        });
    }
    for path in files.keys() {
        if !ownership.contains_key(path) {
            return Err(PackError::Profile(format!(
                "installed file has no RECORD owner: {path}"
            )));
        }
    }
    Ok(NormalizedPackages {
        files,
        distributions,
        inputs,
        omissions,
    })
}

fn csv_path(path: &str) -> String {
    if path.contains([',', '"']) {
        format!("\"{}\"", path.replace('"', "\"\""))
    } else {
        path.to_owned()
    }
}

fn validate_wheel(wheel: &str) -> Result<(), PackError> {
    let mut purelib = None;
    let mut wheel_version = None;
    let mut tags = 0;
    for raw in wheel.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| PackError::Profile("WHEEL contains a malformed header".into()))?;
        let value = value.trim();
        if key.eq_ignore_ascii_case("Root-Is-Purelib") {
            if purelib
                .replace(value.eq_ignore_ascii_case("true"))
                .is_some()
            {
                return Err(PackError::Profile(
                    "WHEEL has duplicate Root-Is-Purelib headers".into(),
                ));
            }
        } else if key.eq_ignore_ascii_case("Wheel-Version") {
            if wheel_version.replace(value).is_some() {
                return Err(PackError::Profile(
                    "WHEEL has duplicate Wheel-Version headers".into(),
                ));
            }
        } else if key.eq_ignore_ascii_case("Tag") {
            let parts: Vec<_> = value.split('-').collect();
            if parts.len() != 3
                || parts[1] != "none"
                || parts[2] != "any"
                || !parts[0]
                    .split('.')
                    .any(|tag| tag == "py3" || tag == "py313")
                || parts[0].split('.').any(|tag| {
                    tag.is_empty() || !tag.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
            {
                return Err(PackError::Profile(
                    "WHEEL requires compatible py3/py313-none-any tags".into(),
                ));
            }
            tags += 1;
        }
    }
    if purelib != Some(true) || tags == 0 || wheel_version != Some("1.0") {
        return Err(PackError::Profile(
            "WHEEL requires version 1.0, Root-Is-Purelib: true and compatible tags".into(),
        ));
    }
    Ok(())
}

fn wrapper_names(entry_points: &str) -> Result<BTreeSet<String>, PackError> {
    let mut group = String::new();
    let mut groups = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut names = BTreeSet::new();
    for raw in entry_points.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            group = line[1..line.len() - 1].to_owned();
            if group.is_empty() || !groups.insert(group.clone()) {
                return Err(PackError::Profile(
                    "entry_points.txt has empty or duplicate groups".into(),
                ));
            }
            continue;
        }
        let (name, value) = line.split_once('=').ok_or_else(|| {
            PackError::Profile("entry_points.txt requires name = object entries".into())
        })?;
        let name = name.trim();
        if group.is_empty()
            || name.is_empty()
            || value.trim().is_empty()
            || !keys.insert((group.clone(), name.to_owned()))
        {
            return Err(PackError::Profile(
                "entry_points.txt has malformed or duplicate entries".into(),
            ));
        }
        if group == "console_scripts" || group == "gui_scripts" {
            if name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || name == "."
                || name == ".."
            {
                return Err(PackError::Profile(
                    "generated wrapper names require bounded ASCII names without path separators"
                        .into(),
                ));
            }
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}

fn validate_direct_url(bytes: &[u8]) -> Result<(), PackError> {
    #[derive(Deserialize)]
    struct DirectUrl {
        dir_info: Option<DirectoryInformation>,
    }
    #[derive(Deserialize)]
    struct DirectoryInformation {
        editable: Option<bool>,
    }
    let url: DirectUrl = serde_json::from_slice(bytes).map_err(|error| {
        PackError::Profile(format!("invalid installed direct_url.json: {error}"))
    })?;
    if url.dir_info.and_then(|directory| directory.editable) == Some(true) {
        return Err(PackError::Profile(
            "editable installed distributions are unsupported".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use glue_format::Archive;
    use serde_json::json;
    use std::{
        io::Cursor,
        sync::atomic::{AtomicU64, Ordering},
    };

    const DIST: &str = "test_demo-1.0.dist-info";
    const RECORD: &str = "test_demo-1.0.dist-info/RECORD";
    const WHEEL: &str = "Wheel-Version: 1.0\nGenerator: controlled-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n";

    struct Fixture {
        directory: PathBuf,
        packages: PathBuf,
        application: PathBuf,
        provider: PathBuf,
        template: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-python-pack-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let packages = directory.join("installed packages Ł");
            let application = directory.join("application");
            let provider = directory.join("provider");
            for root in [&packages, &application, &provider] {
                fs::create_dir(root).unwrap();
            }
            fs::create_dir(application.join("app")).unwrap();
            fs::write(application.join("app/main.py"), b"import test_demo\n").unwrap();
            let mut files = BTreeMap::from([
                ("test_demo/__init__.py".into(), b"answer = 42\n".to_vec()),
                ("test_demo/data/message,one.txt".into(), b"quoted data\n".to_vec()),
                (format!("{DIST}/METADATA"), b"Metadata-Version: 2.3\nName: Test.Demo\nVersion: 1.0\n".to_vec()),
                (format!("{DIST}/WHEEL"), WHEEL.as_bytes().to_vec()),
                (format!("{DIST}/entry_points.txt"), b"[console_scripts]\ntest-demo = test_demo:run\n[plugins]\nanswer = test_demo:answer\n".to_vec()),
                (format!("{DIST}/licenses/LICENSE.txt"), b"fixture license\n".to_vec()),
            ]);
            let record = record_for(&files);
            files.insert(RECORD.into(), record.into_bytes());
            for (path, bytes) in &files {
                write_member(&packages, path, bytes);
            }
            let helpers = BTreeMap::from([
                (
                    "python/archive-importer.py".to_owned(),
                    include_bytes!("../../../fixtures/python-imports/bootstrap.py").to_vec(),
                ),
                (
                    "python/archive-metadata.py".to_owned(),
                    include_bytes!("../../../fixtures/python-metadata/bootstrap.py").to_vec(),
                ),
            ]);
            for (path, bytes) in &helpers {
                write_member(&provider, path, bytes);
            }
            let mut specs: BTreeMap<_, _> = helpers
                .iter()
                .map(|(path, bytes)| {
                    let mut spec = specification(bytes);
                    spec.compression = Compression::Deflate;
                    (path.clone(), spec)
                })
                .collect();
            specs.insert("app/main.py".into(), specification(b""));
            let template = directory.join("template.json");
            fs::write(&template, serde_json::to_vec(&json!({
                "schema_version":0,"app_id":"ingestion.template","entrypoint":"launch",
                "targets":{"linux-arm64":{"os":"linux","arch":"aarch64","minimum_os_version":"7.1.4","abi":{"family":"glibc","minimum_version":"2.36"},"page_sizes":[4096],"cpu_features":[]}},
                "resources":specs,
                "runtimes":{"python":{"target":"linux-arm64","build_id":"pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1","abi":{"language":"python","version":{"major":3,"minor":13,"patch":16},"gil":"conventional","debug":false},"provisioning":{"mode":"host","discovery":"explicit_paths","runtime_library":"/missing Python ingestion provider/lib/libpython3.13.so.1.0","stdlib":"/missing Python ingestion provider/lib/python3.13"},"required_features":[]}},
                "components":{"launch":{"runtime":"python","entry_point":"app/main.py","native_modules":[]}},"native_modules":{},"host_imports":{}
            })).unwrap()).unwrap();
            Self {
                directory,
                packages,
                application,
                provider,
                template,
            }
        }

        fn output(&self, name: &str) -> PathBuf {
            self.directory.join(name)
        }

        fn build(&self, output: &Path) -> Result<PythonBuildReport, PackError> {
            build(
                self.options(PackageInput::SitePackages(&self.packages)),
                output,
            )
        }

        fn options<'a>(&'a self, packages: PackageInput<'a>) -> PythonBuildOptions<'a> {
            PythonBuildOptions {
                provider_template: &self.template,
                provider_root: &self.provider,
                application: &self.application,
                packages,
                app_id: "ingestion.fixture",
                entry: "app/main.py",
            }
        }

        fn append_record(&self, line: &str) {
            let path = self.packages.join(RECORD);
            let mut record = fs::read_to_string(&path).unwrap();
            record.push_str(line);
            fs::write(path, record).unwrap();
        }

        fn rewrite_record(&self) {
            let inventory = scan_tree(&self.packages, &mut ScanBudget::default()).unwrap();
            let files = inventory
                .keys()
                .filter(|path| path.as_str() != RECORD)
                .map(|path| (path.clone(), fs::read(self.packages.join(path)).unwrap()))
                .collect();
            fs::write(self.packages.join(RECORD), record_for(&files)).unwrap();
        }

        fn absent_and_existing_fail(&self) -> String {
            let absent = self.output("absent.glue");
            let error = self.build(&absent).unwrap_err().to_string();
            assert!(!absent.exists(), "{error}");
            let existing = self.output("existing.glue");
            fs::write(&existing, b"preserve user output").unwrap();
            assert!(self.build(&existing).is_err());
            assert_eq!(fs::read(existing).unwrap(), b"preserve user output");
            error
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn write_member(root: &Path, path: &str, bytes: &[u8]) {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }

    fn record_for(files: &BTreeMap<String, Vec<u8>>) -> String {
        let mut record = String::new();
        for (path, bytes) in files {
            record.push_str(&format!(
                "{},{},{}\n",
                csv_path(path),
                packaging::record_hash(bytes),
                bytes.len()
            ));
        }
        record.push_str(&format!("{RECORD},,\n"));
        record
    }

    #[test]
    fn builds_deterministically_preserving_provider_and_original_package_identities() {
        let fixture = Fixture::new();
        let original = fs::read(fixture.packages.join(RECORD)).unwrap();
        let first = fixture.output("first.glue");
        let second = fixture.output("second.glue");
        let report = fixture.build(&first).unwrap();
        assert_eq!(report, fixture.build(&second).unwrap());
        assert_eq!(fs::read(&first).unwrap(), fs::read(second).unwrap());
        assert_eq!(report.distributions.len(), 1);
        assert_eq!(report.distributions[0].name, "test-demo");
        assert_eq!(
            report.distributions[0].original_record_sha256,
            digest(&original)
        );
        assert_eq!(report.distributions[0].retained_files, 7);
        assert!(report.omissions.is_empty());
        assert!(report.inputs.iter().any(|input| input.source == "packages"
            && input.path == RECORD
            && input.sha256 == digest(&original)));
        assert_eq!(fs::read(fixture.packages.join(RECORD)).unwrap(), original);
        let mut archive = Archive::open(Cursor::new(fs::read(first).unwrap())).unwrap();
        let template = Manifest::from_json(&fs::read(&fixture.template).unwrap()).unwrap();
        assert_eq!(archive.manifest().runtimes, template.runtimes);
        assert_eq!(archive.manifest().targets, template.targets);
        assert_eq!(archive.manifest().entrypoint, template.entrypoint);
        assert_eq!(archive.manifest().app_id, "ingestion.fixture");
        assert_eq!(
            archive
                .read_resource("app/python/test_demo/data/message,one.txt")
                .unwrap(),
            b"quoted data\n"
        );
        let rewritten = archive
            .read_resource(&format!("app/python/{RECORD}"))
            .unwrap();
        let rows = packaging::record_rows(std::str::from_utf8(&rewritten).unwrap()).unwrap();
        assert!(rows.windows(2).all(|pair| pair[0][0] < pair[1][0]));
        assert!(rows.contains(&[RECORD.into(), String::new(), String::new()]));
    }

    #[test]
    fn reports_bytecode_and_declared_external_wrappers_without_resolving_them() {
        let fixture = Fixture::new();
        write_member(
            &fixture.packages,
            "test_demo/__pycache__/__init__.cpython-313.pyc",
            b"ignored compiled bytes",
        );
        fixture.append_record("test_demo/__pycache__/__init__.cpython-313.pyc,,\n../../../bin/test-demo,sha256=uninspected,999\n");
        let report = fixture.build(&fixture.output("app.glue")).unwrap();
        assert_eq!(
            report.omissions,
            vec![
                omission("../../../bin/test-demo", "generated_entry_point_wrapper"),
                omission(
                    "test_demo/__pycache__/__init__.cpython-313.pyc",
                    "bytecode_or_cache"
                ),
            ]
        );
        assert!(
            !report
                .inputs
                .iter()
                .any(|input| input.path.ends_with(".pyc") || input.path.starts_with("../"))
        );
        assert_eq!(report.distributions[0].retained_files, 7);
    }

    #[test]
    fn caches_omit_only_bytecode_and_cannot_hide_native_or_source_inputs() {
        for path in [
            "test_demo/__pycache__/native.so",
            "test_demo/__pycache__/source.py",
            "test_demo/__pycache__/asset.txt",
        ] {
            let fixture = Fixture::new();
            write_member(&fixture.packages, path, b"unsupported cache payload");
            fixture.absent_and_existing_fail();
        }
    }

    #[test]
    fn conventional_venv_reads_configuration_and_packages_without_inspecting_interpreter() {
        let fixture = Fixture::new();
        let venv = fixture.directory.join("venv");
        fs::create_dir_all(venv.join("lib/python3.13")).unwrap();
        fs::rename(&fixture.packages, venv.join("lib/python3.13/site-packages")).unwrap();
        fs::write(venv.join("pyvenv.cfg"), "home = /unavailable/interpreter\ninclude-system-site-packages = false\nversion = 3.13.16\nexecutable = /never/run/this/python3.13\n").unwrap();
        #[cfg(unix)]
        {
            fs::create_dir(venv.join("bin")).unwrap();
            std::os::unix::fs::symlink("/does/not/exist", venv.join("bin/python")).unwrap();
            std::os::unix::fs::symlink("lib", venv.join("lib64")).unwrap();
        }
        let report = build(
            fixture.options(PackageInput::Venv(&venv)),
            &fixture.output("venv.glue"),
        )
        .unwrap();
        assert_eq!(report.package_input, "venv");
        assert!(
            report
                .inputs
                .iter()
                .any(|input| input.source == "venv" && input.path == "pyvenv.cfg")
        );
    }

    #[test]
    fn python_requirements_follow_the_template_and_preserve_publication() {
        for requirement in [
            ">=3.14",
            "!=3.13.*",
            "==3.13",
            "~=3.13.17",
            "===3.13.16",
            ">=3.13rc1",
            "",
            "(>=3.9",
            ">=18446744073709551616",
            ">=3.9\n <4",
            ">=3.9\nRequires-Python: <4",
        ] {
            let fixture = Fixture::new();
            fs::write(
                fixture.packages.join(format!("{DIST}/METADATA")),
                format!("Name: Test.Demo\nVersion: 1.0\nRequires-Python: {requirement}\n"),
            )
            .unwrap();
            fixture.rewrite_record();
            // The requirement fails before looking up provider resources.
            fs::remove_dir_all(&fixture.provider).unwrap();
            let error = fixture.absent_and_existing_fail();
            assert!(
                error.contains("Requires-Python"),
                "{requirement:?}: {error}"
            );
        }
        for requirement in [">=3.9", "(>=3.10,<4)", "~=3.13", "==3.13.*"] {
            let fixture = Fixture::new();
            let metadata =
                format!("Name: Test.Demo\nVersion: 1.0\nRequires-Python: {requirement}\n")
                    .into_bytes();
            fs::write(fixture.packages.join(format!("{DIST}/METADATA")), &metadata).unwrap();
            fixture.rewrite_record();
            let output = fixture.output("requirements.glue");
            fixture.build(&output).unwrap();
            let mut archive = Archive::open(File::open(output).unwrap()).unwrap();
            assert_eq!(
                archive
                    .read_resource(&format!("app/python/{DIST}/METADATA"))
                    .unwrap(),
                metadata
            );
        }
    }

    #[test]
    fn venv_python_requirement_is_checked_without_executing_its_interpreter() {
        let fixture = Fixture::new();
        fs::write(
            fixture.packages.join(format!("{DIST}/METADATA")),
            b"Name: Test.Demo\nVersion: 1.0\nRequires-Python: >=3.14\n",
        )
        .unwrap();
        fixture.rewrite_record();
        let venv = fixture.directory.join("venv");
        fs::create_dir_all(venv.join("lib/python3.13")).unwrap();
        fs::rename(&fixture.packages, venv.join("lib/python3.13/site-packages")).unwrap();
        fs::write(venv.join("pyvenv.cfg"), "home = /absent\ninclude-system-site-packages = false\nversion = 3.13.16\nexecutable = /never/executed/python3.13\n").unwrap();
        let output = fixture.output("venv-incompatible.glue");
        let error = build(fixture.options(PackageInput::Venv(&venv)), &output).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("excludes selected CPython 3.13.16")
        );
        assert!(!output.exists());
    }

    #[test]
    fn explicit_application_requirements_reject_before_provider_reads_and_publication() {
        for metadata in [
            b"Name: Application.Only\nVersion: 1\nRequires-Python: >=3.14\n".as_slice(),
            b"Name: Application.Only\nVersion: 1\nRequires-Python: >=3.9\n\xff",
        ] {
            let fixture = Fixture::new();
            write_member(
                &fixture.application,
                "app/python/application_only-1.dist-info/METADATA",
                metadata,
            );
            write_member(
                &fixture.application,
                "app/python/application_only-1.dist-info/RECORD",
                b"application_only-1.dist-info/METADATA,,\napplication_only-1.dist-info/RECORD,,\n",
            );
            fs::remove_dir_all(&fixture.provider).unwrap();
            let error = fixture.absent_and_existing_fail();
            assert!(
                error.contains("Requires-Python") || error.contains("not UTF-8"),
                "{error}"
            );
        }
    }

    #[test]
    fn combined_requirement_checks_leave_nested_metadata_named_assets_opaque() {
        let fixture = Fixture::new();
        let directory = "app/python/application_only-1.dist-info";
        write_member(
            &fixture.application,
            &format!("{directory}/METADATA"),
            b"Name: Application.Only\nVersion: 1\nRequires-Python: >=3.9\n",
        );
        write_member(
            &fixture.application,
            &format!("{directory}/licenses/METADATA"),
            b"\xffRequires-Python: >=4\0",
        );
        write_member(&fixture.application, &format!("{directory}/RECORD"), b"application_only-1.dist-info/METADATA,,\napplication_only-1.dist-info/licenses/METADATA,,\napplication_only-1.dist-info/RECORD,,\n");
        let output = fixture.output("combined.glue");
        fixture.build(&output).unwrap();
        let mut archive = Archive::open(File::open(output).unwrap()).unwrap();
        assert_eq!(
            archive
                .read_resource(&format!("{directory}/licenses/METADATA"))
                .unwrap(),
            b"\xffRequires-Python: >=4\0"
        );
    }

    #[test]
    fn bad_record_integrity_and_paths_preserve_both_absent_and_existing_outputs() {
        for row in [
            "../escape.py,,\n",
            "/absolute.py,,\n",
            "../../../bin/unknown,,\n",
            "../../../bin/test-demo/extra,,\n",
            "test_demo/__init__.py,,\n",
            "test_demo/missing.py,,\n",
            "other-1.dist-info/METADATA,,\n",
            "test_demo/__pycache__/duplicate.pyc,,\ntest_demo/__pycache__/duplicate.pyc,,\n",
            "../../../bin/test-demo,,\n../../../bin/test-demo,,\n",
        ] {
            let fixture = Fixture::new();
            fixture.append_record(row);
            fixture.absent_and_existing_fail();
        }
        for replacement in [
            "test_demo/__init__.py,sha256=wrong,12",
            "test_demo/__init__.py,,999",
            "test_demo/__init__.py,,+12",
            "test_demo/__init__.py,sha512=wrong,",
        ] {
            let fixture = Fixture::new();
            let record = fs::read_to_string(fixture.packages.join(RECORD)).unwrap();
            let record = record
                .lines()
                .map(|line| {
                    if line.starts_with("test_demo/__init__.py,") {
                        replacement
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(fixture.packages.join(RECORD), record).unwrap();
            assert!(fixture.absent_and_existing_fail().contains("differs"));
        }
    }

    #[test]
    fn closed_inventory_rejects_unowned_files_and_missing_record_self_entry() {
        let fixture = Fixture::new();
        write_member(&fixture.packages, "unowned.txt", b"not owned");
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("no RECORD owner")
        );
        let fixture = Fixture::new();
        let record = fs::read_to_string(fixture.packages.join(RECORD)).unwrap();
        fs::write(
            fixture.packages.join(RECORD),
            record.replace(&format!("{RECORD},,\n"), ""),
        )
        .unwrap();
        assert!(fixture.absent_and_existing_fail().contains("self-entry"));
        let fixture = Fixture::new();
        fs::remove_file(
            fixture
                .packages
                .join(format!("{DIST}/licenses/LICENSE.txt")),
        )
        .unwrap();
        assert!(fixture.absent_and_existing_fail().contains("missing file"));
    }

    #[test]
    fn native_hooks_legacy_and_editable_inputs_are_rejected() {
        for path in [
            "module.so",
            "module.so.1",
            "module.pyd",
            "module.LIB",
            "hook.pth",
            "old.egg-info/PKG-INFO",
            "old.egg-link",
            "old.egg/file.py",
        ] {
            let fixture = Fixture::new();
            write_member(&fixture.packages, path, b"unsupported");
            fixture.absent_and_existing_fail();
        }
        for direct_url in [
            br#"{"url":"file:///source","dir_info":{"editable":true}}"#.as_slice(),
            br#"{"dir_info":{"editable":true,"editable":false}}"#,
            br#"{"dir_info":{"editable":true},"dir_info":{"editable":false}}"#,
            br#"{"dir_info":{"editable":"false"}}"#,
        ] {
            let fixture = Fixture::new();
            write_member(
                &fixture.packages,
                &format!("{DIST}/direct_url.json"),
                direct_url,
            );
            fixture.rewrite_record();
            fixture.absent_and_existing_fail();
        }
        validate_direct_url(br#"{"url":"file:///source","dir_info":{"editable":false}}"#).unwrap();
        validate_direct_url(br#"{"url":"https://example.invalid/source","archive_info":{"hashes":{"sha256":"declared"}}}"#).unwrap();
    }

    #[test]
    fn wheel_requires_pure_compatible_declarations_and_supports_compressed_interpreter_tags() {
        for wheel in [
            WHEEL.replace("true", "false"),
            WHEEL.replace("py3-none-any", "cp313-cp313-linux_aarch64"),
            WHEEL.replace("py3-none-any", "py2-none-any"),
            WHEEL.replace("py3-none-any", "py3-none-macosx"),
            WHEEL.replace("py3-none-any", "py3-abi3-any"),
            WHEEL.replace("1.0", "2.0"),
            format!("{WHEEL}Root-Is-Purelib: true\n"),
            WHEEL.replace("Tag: py3-none-any\n", ""),
        ] {
            let fixture = Fixture::new();
            fs::write(fixture.packages.join(format!("{DIST}/WHEEL")), wheel).unwrap();
            fixture.rewrite_record();
            assert!(fixture.absent_and_existing_fail().contains("WHEEL"));
        }
        validate_wheel(&WHEEL.replace("py3-none-any", "py2.py3-none-any")).unwrap();
        validate_wheel(&WHEEL.replace("py3-none-any", "py313-none-any")).unwrap();
    }

    #[test]
    fn venv_rejects_wrong_versions_system_sites_duplicates_and_ambiguous_layouts() {
        for configuration in [
            "include-system-site-packages = true\nversion = 3.13.16\n",
            "include-system-site-packages = false\nversion = 3.12.8\n",
            "include-system-site-packages = false\nversion = 3.13.16t\n",
            "include-system-site-packages = false\nversion = 3.13\n",
            "include-system-site-packages = false\nversion = 3.13.16\nversion = 3.13.16\n",
            "include-system-site-packages = false\nversion = 3.13.16\nfree-threaded = true\n",
            "include-system-site-packages = false\nversion = 3.13.16\nexecutable = /bin/python3.13t\n",
        ] {
            let fixture = Fixture::new();
            fs::write(fixture.directory.join("pyvenv.cfg"), configuration).unwrap();
            assert!(venv_packages(&fixture.directory, &mut Vec::new()).is_err());
        }
        for extra in ["lib/python3.14", "lib/python3.13t", "Lib"] {
            let fixture = Fixture::new();
            fs::write(
                fixture.directory.join("pyvenv.cfg"),
                "include-system-site-packages = false\nversion = 3.13.16\n",
            )
            .unwrap();
            fs::create_dir_all(fixture.directory.join(extra)).unwrap();
            fs::create_dir_all(fixture.directory.join("lib/python3.13/site-packages")).unwrap();
            assert!(venv_packages(&fixture.directory, &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn application_package_stdlib_and_case_collisions_are_rejected() {
        let fixture = Fixture::new();
        write_member(
            &fixture.application,
            "app/python/test_demo/__init__.py",
            b"collision\n",
        );
        assert!(fixture.absent_and_existing_fail().contains("collides"));
        let fixture = Fixture::new();
        write_member(&fixture.packages, "os.py", b"shadow = True\n");
        fixture.rewrite_record();
        let error = fixture.absent_and_existing_fail();
        assert!(error.contains("shadows host runtime module"), "{error}");
        // This collision is between separate input roots and also occurs on
        // builders whose own filesystem cannot contain case-only siblings.
        let fixture = Fixture::new();
        write_member(
            &fixture.application,
            "app/python/Test_Demo/__init__.py",
            b"collision\n",
        );
        assert!(fixture.absent_and_existing_fail().contains("case"));
    }

    #[test]
    fn original_metadata_file_application_and_scan_bounds_apply_before_publication() {
        let fixture = Fixture::new();
        fs::write(
            fixture.packages.join(format!("{DIST}/METADATA")),
            vec![b'x'; MAX_METADATA as usize + 1],
        )
        .unwrap();
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("metadata bytes")
        );
        let fixture = Fixture::new();
        fs::write(
            fixture.packages.join(RECORD),
            vec![b'x'; MAX_RECORD as usize + 1],
        )
        .unwrap();
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("metadata bytes")
        );
        let fixture = Fixture::new();
        write_member(
            &fixture.packages,
            "large.txt",
            &vec![b'x'; MAX_FILE_BYTES as usize + 1],
        );
        assert!(fixture.absent_and_existing_fail().contains("bytes"));
        let fixture = Fixture::new();
        for index in 0..1024 {
            write_member(&fixture.packages, &format!("many/{index}.txt"), b"");
        }
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("application files")
        );
        let fixture = Fixture::new();
        write_member(
            &fixture.packages,
            "a.txt",
            &vec![b'x'; MAX_FILE_BYTES as usize],
        );
        write_member(
            &fixture.packages,
            "b.txt",
            &vec![b'x'; MAX_FILE_BYTES as usize],
        );
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("application bytes")
        );
        let fixture = Fixture::new();
        let nested = vec!["deep"; MAX_SCAN_DEPTH as usize + 1].join("/");
        fs::create_dir_all(fixture.packages.join(nested)).unwrap();
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("directory depth")
        );
    }

    #[test]
    fn distribution_identity_and_shared_ownership_are_validated_before_filtering() {
        let fixture = Fixture::new();
        fs::write(
            fixture.packages.join(format!("{DIST}/METADATA")),
            "Name: Other\nVersion: 1.0\n",
        )
        .unwrap();
        fixture.rewrite_record();
        assert!(fixture.absent_and_existing_fail().contains("Name/Version"));
        let fixture = Fixture::new();
        write_member(
            &fixture.packages,
            "other-1.dist-info/METADATA",
            b"Name: Other\nVersion: 1\n",
        );
        write_member(
            &fixture.packages,
            "other-1.dist-info/WHEEL",
            WHEEL.as_bytes(),
        );
        write_member(&fixture.packages, "other-1.dist-info/RECORD", b"other-1.dist-info/METADATA,,\nother-1.dist-info/WHEEL,,\nother-1.dist-info/RECORD,,\ntest_demo/__init__.py,,\n");
        assert!(
            fixture
                .absent_and_existing_fail()
                .contains("share RECORD ownership")
        );
    }

    #[cfg(unix)]
    #[test]
    fn roots_files_directory_components_and_even_cache_symlinks_are_rejected() {
        for path in [
            "test_demo/__init__.py",
            "test_demo",
            "test_demo/__pycache__/ignored.pyc",
        ] {
            let fixture = Fixture::new();
            let input = fixture.packages.join(path);
            if input.is_dir() {
                fs::remove_dir_all(&input).unwrap();
            } else if input.exists() {
                fs::remove_file(&input).unwrap();
            }
            fs::create_dir_all(input.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink("/does/not/exist", &input).unwrap();
            assert!(fixture.absent_and_existing_fail().contains("symlink"));
        }
        let fixture = Fixture::new();
        let link = fixture.directory.join("package-link");
        std::os::unix::fs::symlink(&fixture.packages, &link).unwrap();
        assert!(
            build(
                fixture.options(PackageInput::SitePackages(&link)),
                &fixture.output("absent.glue")
            )
            .is_err()
        );
        let user = fixture.output("user-file");
        let output = fixture.output("output-link");
        fs::write(&user, b"preserve me").unwrap();
        std::os::unix::fs::symlink(&user, &output).unwrap();
        assert!(fixture.build(&output).is_err());
        assert_eq!(fs::read(user).unwrap(), b"preserve me");
    }
}
