//! Preserve existing project/package bytes and metadata without importing them.
use super::discovery::{ResolvedEnvironment, read_bounded};
use super::failure::Failure;
use glue_format::{Diagnostic, DiagnosticCode};
use glue_format::{InputIdentity, ResourcePath};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PythonEntry {
    File(String),
    Module(String),
    ConsoleScript(String),
}
#[derive(Clone, Debug)]
pub struct InventoryOptions {
    pub project: PathBuf,
    pub entry: PythonEntry,
    pub output: Option<PathBuf>,
    pub prune: BTreeSet<String>,
    pub max_files: usize,
    pub max_bytes: u64,
}
impl InventoryOptions {
    pub fn new(project: PathBuf, entry: PythonEntry) -> Self {
        Self {
            project,
            entry,
            output: None,
            prune: BTreeSet::new(),
            max_files: 100_000,
            max_bytes: 1024 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationIndex {
    pub revision: u32,
    pub import_roots: Vec<String>,
    pub entry: PythonEntry,
    pub native: BTreeMap<String, String>,
}
#[derive(Debug)]
pub struct PythonInventory {
    pub resources: BTreeMap<String, Vec<u8>>,
    pub native_files: BTreeMap<String, PathBuf>,
    pub inputs: BTreeMap<String, InputIdentity>,
    pub omissions: BTreeMap<String, String>,
    pub unowned: Vec<String>,
    pub index: ApplicationIndex,
}

struct Scan<'a> {
    roots_excluded: Vec<PathBuf>,
    prune: &'a BTreeSet<String>,
    files: usize,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
    omissions: BTreeMap<String, String>,
}
pub(crate) type RuntimeTreeInventory = (BTreeMap<String, PathBuf>, BTreeMap<String, String>);
pub(crate) fn runtime_stdlib_files(
    prefix: &Path,
    stdlib: &Path,
) -> Result<RuntimeTreeInventory, String> {
    let prune = BTreeSet::new();
    let mut scan = Scan {
        roots_excluded: vec![stdlib.join("site-packages")],
        prune: &prune,
        files: 0,
        bytes: 0,
        max_files: 100_000,
        max_bytes: 1024 * 1024 * 1024,
        omissions: BTreeMap::new(),
    };
    let logical = stdlib
        .strip_prefix(prefix)
        .map_err(|e| e.to_string())?
        .to_str()
        .ok_or("non-UTF8 stdlib prefix")?
        .replace('\\', "/");
    let mut files = BTreeMap::new();
    scan.walk(prefix, stdlib, &logical, &mut BTreeSet::new(), &mut files)?;
    Ok((files, scan.omissions))
}
impl Scan<'_> {
    fn walk(
        &mut self,
        root: &Path,
        directory: &Path,
        logical: &str,
        ancestors: &mut BTreeSet<PathBuf>,
        result: &mut BTreeMap<String, PathBuf>,
    ) -> Result<(), String> {
        let actual = fs::canonicalize(directory).map_err(|e| format!("{directory:?}: {e}"))?;
        if !actual.starts_with(root) {
            return Err(format!("Python input symlink escapes root: {directory:?}"));
        }
        if !ancestors.insert(actual.clone()) {
            return Err("Python directory symlink cycle".into());
        }
        if ancestors.len() > 128 {
            return Err("Python directory depth exceeds bound".into());
        }
        let mut entries = fs::read_dir(directory)
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 Python input name")?;
            let path = entry.path();
            let key = format!("{logical}/{name}");
            self.files += 1;
            if self.files > self.max_files {
                return Err("Python inventory exceeds file/directory bound".into());
            }
            if name == ".git"
                || name == "__pycache__"
                || name.ends_with(".pyc")
                || name.ends_with(".pyo")
                || name.starts_with(".glue-stage-")
            {
                self.omissions.insert(key, "cache_or_build_control".into());
                continue;
            }
            if self
                .prune
                .iter()
                .any(|prefix| key == *prefix || key.starts_with(&format!("{prefix}/")))
            {
                self.omissions.insert(key, "explicit_pruning".into());
                continue;
            }
            // Exclude a known venv/output before resolving its legitimate base
            // interpreter symlink, which may leave the project directory.
            if self.roots_excluded.contains(&path) {
                self.omissions
                    .insert(key, "environment_or_output_root".into());
                continue;
            }
            let resolved = fs::canonicalize(&path).map_err(|e| format!("{path:?}: {e}"))?;
            if !resolved.starts_with(root) {
                return Err(format!("Python input symlink escapes root: {path:?}"));
            }
            if path.is_dir() {
                self.walk(root, &path, &key, ancestors, result)?;
            } else if path.is_file() {
                ResourcePath::new(&key).map_err(|e| e.to_string())?;
                self.bytes = self
                    .bytes
                    .checked_add(fs::metadata(&resolved).map_err(|e| e.to_string())?.len())
                    .ok_or("Python byte count overflow")?;
                if self.bytes > self.max_bytes {
                    return Err("Python inventory exceeds byte bound".into());
                }
                result.insert(key, resolved);
            } else {
                return Err(format!("nonregular Python input {path:?}"));
            }
        }
        ancestors.remove(&actual);
        Ok(())
    }
}

pub fn collect(
    environment: &ResolvedEnvironment,
    options: &InventoryOptions,
) -> Result<PythonInventory, String> {
    collect_diagnostic(environment, options).map_err(|e| e.to_string())
}
pub fn collect_diagnostic(
    environment: &ResolvedEnvironment,
    options: &InventoryOptions,
) -> Result<PythonInventory, Diagnostic> {
    collect_impl(environment, options).map_err(|e| e.0)
}
fn collect_impl(
    environment: &ResolvedEnvironment,
    options: &InventoryOptions,
) -> Result<PythonInventory, Failure> {
    let project = fs::canonicalize(&options.project)
        .map_err(|e| Failure::new(DiagnosticCode::MissingInput, e.to_string()))?;
    let mut excluded = vec![
        environment.environment.clone(),
        environment.runtime.prefix.clone(),
    ];
    if let Some(output) = &options.output {
        excluded.push(fs::canonicalize(output).unwrap_or_else(|_| {
            if output.is_absolute() {
                output.clone()
            } else {
                project.join(output)
            }
        }));
    }
    let mut scan = Scan {
        roots_excluded: excluded,
        prune: &options.prune,
        files: 0,
        bytes: 0,
        max_files: options.max_files,
        max_bytes: options.max_bytes,
        omissions: BTreeMap::new(),
    };
    let mut files = BTreeMap::new();
    scan.walk(
        &project,
        &project,
        "app/project",
        &mut BTreeSet::new(),
        &mut files,
    )?;
    let mut import_roots = vec!["app/project".to_owned()];
    for (index, root) in environment.site_packages.iter().enumerate() {
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let logical = format!("app/site/{index}");
        import_roots.push(logical.clone());
        scan.walk(&root, &root, &logical, &mut BTreeSet::new(), &mut files)?;
    }
    let mut resources = BTreeMap::new();
    let mut native_files = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    for (key, path) in &files {
        let bytes = read_bounded(path, 256 * 1024 * 1024)?;
        inputs.insert(key.clone(), InputIdentity::of(&bytes));
        let native = bytes.starts_with(b"\x7fELF")
            || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
            || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
            || key.ends_with(".dylib")
            || key.contains(".so.")
            || environment
                .runtime
                .extension_suffixes
                .iter()
                .any(|suffix| key.ends_with(suffix));
        if native {
            native_files.insert(key.clone(), path.clone());
        } else {
            resources.insert(key.clone(), bytes);
        }
    }
    for (key, bytes) in &resources {
        if key.ends_with(".egg-link") {
            return Err(Failure::new(
                DiagnosticCode::UnsupportedCapability,
                format!(
                    "editable .egg-link is unsupported: {key}; install a non-editable package before building"
                ),
            ));
        }
        if key.ends_with("/direct_url.json") {
            let value: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| format!("invalid direct_url metadata {key}: {e}"))?;
            if value
                .pointer("/dir_info/editable")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                return Err(Failure::new(
                    DiagnosticCode::UnsupportedCapability,
                    format!("editable distribution is unsupported: {key}"),
                ));
            }
        }
        if key.ends_with(".pth") {
            if !import_roots.iter().any(|root| {
                root.starts_with("app/site/")
                    && key
                        .rsplit_once('/')
                        .is_some_and(|(parent, _)| parent == root)
            }) {
                continue;
            }
            let site_root = import_roots
                .iter()
                .filter(|root| {
                    root.starts_with("app/site/") && key.starts_with(&format!("{root}/"))
                })
                .max_by_key(|root| root.len())
                .ok_or_else(|| format!("project .pth needs explicit configuration: {key}"))?;
            let root_index = site_root
                .rsplit('/')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or("invalid site index")?;
            let root = fs::canonicalize(&environment.site_packages[root_index])
                .map_err(|e| e.to_string())?;
            let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
            let mut additional = Vec::new();
            for line in text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
            {
                if line.starts_with("import ") || line.starts_with("import\t") {
                    return Err(Failure::new(
                        DiagnosticCode::UnsupportedCapability,
                        format!(
                            "executable .pth is unsupported: {key}; replace it with declared internal paths"
                        ),
                    ));
                }
                let path = fs::canonicalize(root.join(line))
                    .map_err(|e| format!("missing .pth path {key}: {e}"))?;
                let relative = path
                    .strip_prefix(&root)
                    .map_err(|_| format!(".pth path escapes site-packages: {key}"))?;
                if !path.is_dir() {
                    return Err(Failure::new(
                        DiagnosticCode::UnsupportedCapability,
                        format!(".pth path must be an internal directory: {key}"),
                    ));
                }
                let logical = format!(
                    "{site_root}/{}",
                    relative.to_string_lossy().replace('\\', "/")
                );
                ResourcePath::new(&logical).map_err(|e| e.to_string())?;
                additional.push(logical);
            }
            import_roots.extend(additional);
        }
    }
    import_roots.dedup();
    let mut owned = BTreeSet::new();
    let mut omissions = scan.omissions;
    for (key, bytes) in resources
        .iter()
        .filter(|(key, _)| key.ends_with(".dist-info/RECORD"))
    {
        let root = key
            .rsplit_once('/')
            .and_then(|(directory, _)| directory.rsplit_once('/'))
            .map(|(root, _)| root)
            .ok_or("invalid RECORD path")?;
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        for [name, hash, size] in record_rows(text)? {
            if name.starts_with("../") {
                if name.starts_with("../../../bin/") && !name[13..].contains('/') {
                    omissions.insert(
                        format!("{root}/{name}"),
                        "generated_environment_wrapper".into(),
                    );
                    continue;
                }
                return Err(Failure::new(
                    DiagnosticCode::UnsupportedCapability,
                    format!(
                        "RECORD references external data {name}; provide an explicit resource mapping"
                    ),
                ));
            }
            ResourcePath::new(&name).map_err(|e| e.to_string())?;
            let logical = format!("{root}/{name}");
            if !owned.insert(logical.clone()) {
                return Err(Failure::new(
                    DiagnosticCode::InvalidConfiguration,
                    format!("duplicate RECORD ownership: {logical}"),
                ));
            }
            let Some(identity) = inputs.get(&logical) else {
                if name.contains("__pycache__/") || name.ends_with(".pyc") {
                    continue;
                }
                return Err(Failure::new(
                    DiagnosticCode::MissingInput,
                    format!("RECORD references missing installed file: {logical}"),
                ));
            };
            if !size.is_empty() && size.parse::<u64>().ok() != Some(identity.size) {
                return Err(Failure::new(
                    DiagnosticCode::PayloadIntegrity,
                    format!("RECORD size differs: {logical}"),
                ));
            }
            if !hash.is_empty() && hash != record_hash(&identity.sha256)? {
                return Err(Failure::new(
                    DiagnosticCode::PayloadIntegrity,
                    format!("RECORD SHA-256 differs or unsupported hash algorithm: {logical}"),
                ));
            }
        }
    }
    let unowned = inputs
        .keys()
        .filter(|key| key.starts_with("app/site/") && !owned.contains(*key))
        .cloned()
        .collect();
    let entry = match &options.entry {
        PythonEntry::File(path) => {
            ResourcePath::new(path).map_err(|e| e.to_string())?;
            let key = format!("app/project/{path}");
            if !resources.contains_key(&key) {
                return Err(Failure::new(
                    DiagnosticCode::MissingEntry,
                    format!("missing Python entry source {path}"),
                ));
            }
            PythonEntry::File(key)
        }
        PythonEntry::Module(module) => {
            validate_module(module)?;
            let relative = module.replace('.', "/");
            if !import_roots.iter().any(|root| {
                resources.contains_key(&format!("{root}/{relative}.py"))
                    || resources.contains_key(&format!("{root}/{relative}/__main__.py"))
            }) {
                return Err(Failure::new(
                    DiagnosticCode::MissingEntry,
                    format!("missing executable Python module {module}"),
                ));
            }
            PythonEntry::Module(module.clone())
        }
        PythonEntry::ConsoleScript(name) => {
            let target = environment
                .console_scripts
                .get(name)
                .cloned()
                .ok_or_else(|| {
                    Failure::new(
                        DiagnosticCode::MissingEntry,
                        format!(
                            "console script {name} is absent; available: {:?}",
                            environment.console_scripts.keys().collect::<Vec<_>>()
                        ),
                    )
                })?;
            let callable = target.split('[').next().unwrap_or("").trim();
            let (module, attribute) = callable.split_once(':').ok_or("invalid console callable")?;
            validate_module(module)?;
            validate_module(attribute)?;
            PythonEntry::ConsoleScript(target)
        }
    };
    let index = ApplicationIndex {
        revision: 1,
        import_roots,
        entry,
        native: BTreeMap::new(),
    };
    resources.insert(
        "support/python-index.json".into(),
        serde_json::to_vec(&index).map_err(|e| e.to_string())?,
    );
    Ok(PythonInventory {
        resources,
        native_files,
        inputs,
        omissions,
        unowned,
        index,
    })
}

pub fn validate_module(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.split('.').any(|part| {
            part.is_empty()
                || !part.chars().enumerate().all(|(index, c)| {
                    c == '_' || c.is_ascii_alphanumeric() && (index > 0 || !c.is_ascii_digit())
                })
        })
    {
        Err(format!("invalid Python module name {name}"))
    } else {
        Ok(())
    }
}

fn record_hash(hex: &str) -> Result<String, String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::from("sha256=");
    let mut bits = 0u32;
    let mut count = 0u8;
    for byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        count += 8;
        while count >= 6 {
            count -= 6;
            output.push(alphabet[((bits >> count) & 63) as usize] as char);
        }
    }
    if count > 0 {
        output.push(alphabet[((bits << (6 - count)) & 63) as usize] as char);
    }
    Ok(output)
}

/// Bounded CSV RECORD parsing without the legacy 1,024-row fixture restriction.
pub fn record_rows(text: &str) -> Result<Vec<[String; 3]>, String> {
    if text.len() > 16 * 1024 * 1024 {
        return Err("RECORD exceeds 16 MiB".into());
    }
    let mut rows = Vec::new();
    for line in text.lines() {
        if rows.len() >= 100_000 {
            return Err("RECORD exceeds 100,000 rows".into());
        }
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut state = 0u8;
        let mut chars = line.trim_end_matches('\r').chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if state == 1 && chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' if state == 1 => state = 2,
                '"' if state == 0 && field.is_empty() => state = 1,
                '"' => return Err("malformed RECORD CSV quote".into()),
                ',' if state != 1 => {
                    fields.push(std::mem::take(&mut field));
                    state = 0;
                }
                _ if state == 2 => return Err("characters follow closing RECORD CSV quote".into()),
                _ => field.push(c),
            }
        }
        fields.push(field);
        if state == 1 || fields.len() != 3 {
            return Err("malformed three-column RECORD CSV".into());
        }
        rows.push(fields.try_into().map_err(|_| "invalid RECORD row")?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_match_standard_record_spelling() {
        assert_eq!(
            record_hash(&glue_format::digest(b"")).unwrap(),
            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }
    #[test]
    fn csv_scales_and_preserves_quoted_paths() {
        assert_eq!(
            record_rows("\"name,one.txt\",,\n").unwrap()[0][0],
            "name,one.txt"
        );
        assert_eq!(record_rows(&"file,,\n".repeat(10000)).unwrap().len(), 10000);
        assert!(record_rows("\"bad\"quote,,\n").is_err());
    }
    #[test]
    fn modules_are_not_code() {
        assert!(validate_module("pkg.main").is_ok());
        assert!(validate_module("pkg;print(1)").is_err());
    }
}
