//! Installed Node project ingestion. Never invokes npm, scripts, node-gyp or tsc.
use crate::distribution::{DistributionInput, DistributionLimits, PayloadSource, Result};
use glue_format::{Diagnostic, DiagnosticCode, ResourcePath};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "supply an installed Node project, explicit entry and compatible runtime; no installation or build scripts are run",
    )
}
#[derive(Clone, Debug)]
pub struct NodeBuildOptions {
    pub project: PathBuf,
    pub entry: Option<PathBuf>,
    pub node: PathBuf,
    pub bridge: PathBuf,
    pub target: Option<String>,
    pub host: bool,
    pub native_search: Vec<PathBuf>,
    pub normalize_native_paths: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleFile {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_api: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub package_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<Value>,
    pub dependencies: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleIndex {
    pub schema_version: u32,
    pub entry: String,
    pub files: BTreeMap<String, ModuleFile>,
    pub packages: BTreeMap<String, PackageRecord>,
}
#[derive(Clone, Debug)]
pub struct NodeProject {
    pub root: PathBuf,
    pub app_id: String,
    pub index: ModuleIndex,
    pub resources: BTreeMap<String, Vec<u8>>,
    pub native_addons: BTreeMap<String, PathBuf>,
    pub native_files: BTreeMap<String, PathBuf>,
    pub omissions: BTreeMap<String, String>,
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    let p = path
        .strip_prefix(root)
        .map_err(|_| {
            error(
                DiagnosticCode::PathEscape,
                format!("{} escapes project", path.display()),
            )
        })?
        .to_str()
        .ok_or_else(|| error(DiagnosticCode::PathEscape, "non-UTF8 project path"))?
        .replace('\\', "/");
    if !p.is_empty() {
        ResourcePath::new(&p).map_err(|e| error(DiagnosticCode::PathEscape, e.to_string()))?;
    }
    Ok(p)
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = fs::File::open(path).map_err(|e| {
        error(
            DiagnosticCode::MissingInput,
            format!("{}: {e}", path.display()),
        )
    })?;
    if f.metadata()
        .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?
        .len()
        > max
    {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            format!("{} exceeds {max} bytes", path.display()),
        ));
    }
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    if b.len() as u64 > max {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "input grew beyond bound",
        ));
    }
    Ok(b)
}
fn native_file(path: &str) -> bool {
    path.ends_with(".node")
        || path.ends_with(".dylib")
        || path.ends_with(".so")
        || path.contains(".so.")
}
struct Walk<'a> {
    root: &'a Path,
    excluded: Option<&'a Path>,
    files: BTreeMap<String, Vec<u8>>,
    native: BTreeMap<String, PathBuf>,
    seen: BTreeSet<PathBuf>,
    total: u64,
}
impl Walk<'_> {
    fn visit(&mut self, dir: &Path) -> Result<()> {
        let canonical = fs::canonicalize(dir)
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
        if !canonical.starts_with(self.root) {
            return Err(error(
                DiagnosticCode::PathEscape,
                format!("{} escapes project", dir.display()),
            ));
        }
        if self.excluded.is_some_and(|p| canonical.starts_with(p))
            || !self.seen.insert(canonical.clone())
        {
            return Ok(());
        }
        let mut entries: Vec<_> = fs::read_dir(&canonical)
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name == ".git"
                || name == ".DS_Store"
                || name.to_string_lossy().starts_with(".glue-stage-")
            {
                continue;
            }
            let path = entry.path();
            let target = fs::canonicalize(&path).map_err(|e| {
                error(
                    DiagnosticCode::MissingInput,
                    format!("{}: {e}", path.display()),
                )
            })?;
            if !target.starts_with(self.root) {
                return Err(error(
                    DiagnosticCode::PathEscape,
                    format!("symlink {} escapes project", path.display()),
                ));
            }
            if self.excluded.is_some_and(|p| target.starts_with(p)) {
                continue;
            }
            let metadata = fs::metadata(&target)
                .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
            if metadata.is_dir() {
                self.visit(&target)?;
            } else if metadata.is_file() {
                let name = relative(self.root, &target)?;
                if self.files.len() + self.native.len() >= 100_000 {
                    return Err(error(
                        DiagnosticCode::ResourceLimit,
                        "Node input exceeds 100,000 files",
                    ));
                }
                if native_file(&name) {
                    self.native.insert(name, target);
                } else {
                    let bytes = read(&target, 64 * 1024 * 1024)?;
                    self.total += bytes.len() as u64;
                    if self.total > 1024 * 1024 * 1024 {
                        return Err(error(
                            DiagnosticCode::ResourceLimit,
                            "Node source/resources exceed 1 GiB",
                        ));
                    }
                    self.files.insert(name, bytes);
                }
            } else {
                return Err(error(
                    DiagnosticCode::UnsupportedCapability,
                    "special project files are unsupported",
                ));
            }
        }
        Ok(())
    }
}
fn metadata(bytes: &[u8], path: &str) -> Result<Value> {
    if bytes.len() > 1024 * 1024 {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            format!("{path} exceeds 1 MiB metadata bound"),
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, format!("{path}: {e}")))?;
    if !value.is_object() {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            format!("{path} must contain an object"),
        ));
    }
    Ok(value)
}
fn dependency(root: &Path, package: &Path, name: &str) -> Result<Option<PathBuf>> {
    if name.is_empty()
        || name.contains(['\\', ':'])
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || (!name.starts_with('@') && name.contains('/'))
        || (name.starts_with('@') && name.split('/').count() != 2)
    {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            format!("invalid dependency name {name}"),
        ));
    }
    let mut dir = Some(package);
    while let Some(current) = dir {
        if !current.starts_with(root) {
            break;
        }
        let candidate = current.join("node_modules").join(name);
        if candidate.exists() {
            let resolved = fs::canonicalize(&candidate)
                .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
            if !resolved.starts_with(root) {
                return Err(error(
                    DiagnosticCode::PathEscape,
                    format!("dependency {name} escapes project"),
                ));
            }
            return Ok(Some(resolved));
        }
        dir = current.parent();
    }
    Ok(None)
}
/// Inventory ordinary npm/pnpm installed graphs without executing any project code.
pub fn ingest(project: &Path, entry: Option<&Path>, output: Option<&Path>) -> Result<NodeProject> {
    let root = fs::canonicalize(project)
        .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    if root.join(".pnp.cjs").exists() || root.join(".pnp.loader.mjs").exists() {
        return Err(error(
            DiagnosticCode::UnsupportedCapability,
            "Yarn Plug'n'Play requires an unsupported runtime loader; supply an installed node_modules graph",
        ));
    }
    let excluded = output.map(|p| {
        if p.is_absolute() {
            p.to_owned()
        } else {
            std::env::current_dir().unwrap_or_default().join(p)
        }
    });
    let mut walk = Walk {
        root: &root,
        excluded: excluded.as_deref(),
        files: BTreeMap::new(),
        native: BTreeMap::new(),
        seen: BTreeSet::new(),
        total: 0,
    };
    walk.visit(&root)?;
    let mut raw = BTreeMap::new();
    for (path, bytes) in &walk.files {
        if path == "package.json" || path.ends_with("/package.json") {
            let dir = path
                .strip_suffix("package.json")
                .unwrap()
                .trim_end_matches('/')
                .to_owned();
            raw.insert(dir, metadata(bytes, path)?);
        }
    }
    let app = raw.get("").ok_or_else(|| {
        error(
            DiagnosticCode::MissingInput,
            "project package.json is missing",
        )
    })?;
    let app_id = app
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("node-app")
        .to_owned();
    let entry = match entry {
        Some(path) => root.join(path),
        None => {
            if let Some(main) = app.get("main").and_then(Value::as_str) {
                root.join(main)
            } else if root.join("index.js").is_file() {
                root.join("index.js")
            } else {
                return Err(error(
                    DiagnosticCode::MissingEntry,
                    "entry is ambiguous; pass --entry for prebuilt JavaScript output",
                ));
            }
        }
    };
    let entry = fs::canonicalize(&entry).map_err(|e| {
        error(
            DiagnosticCode::MissingEntry,
            format!("{}: {e}", entry.display()),
        )
    })?;
    let entry = relative(&root, &entry)?;
    if ![".js", ".cjs", ".mjs"].iter().any(|s| entry.ends_with(s)) {
        return Err(error(
            DiagnosticCode::UnsupportedCapability,
            "entry must be prebuilt .js/.cjs/.mjs; TypeScript/build scripts are never executed",
        ));
    }
    let mut packages = BTreeMap::new();
    let mut omissions = BTreeMap::new();
    for (dir, value) in &raw {
        let package_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("commonjs");
        if !["commonjs", "module"].contains(&package_type) {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                format!("invalid package type at {dir}"),
            ));
        }
        let mut dependencies = BTreeMap::new();
        for section in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "devDependencies",
        ] {
            if let Some(specs) = value.get(section) {
                let specs = specs.as_object().ok_or_else(|| {
                    error(
                        DiagnosticCode::InvalidConfiguration,
                        format!("{section} must be an object"),
                    )
                })?;
                for name in specs.keys() {
                    if dependencies.contains_key(name) {
                        continue;
                    }
                    match dependency(&root, &root.join(dir), name)? {
                        Some(target) => {
                            let logical = relative(&root, &target)?;
                            if !raw.contains_key(&logical) {
                                return Err(error(
                                    DiagnosticCode::MissingDependency,
                                    format!("dependency {name} lacks package.json"),
                                ));
                            }
                            dependencies.insert(name.clone(), logical);
                        }
                        None => {
                            let optional = section == "optionalDependencies"
                                || section == "devDependencies"
                                || value
                                    .get("optionalDependencies")
                                    .and_then(|v| v.get(name))
                                    .is_some()
                                || value
                                    .get("peerDependenciesMeta")
                                    .and_then(|v| v.get(name))
                                    .and_then(|v| v.get("optional"))
                                    .and_then(Value::as_bool)
                                    == Some(true);
                            if optional {
                                omissions.insert(format!("{dir}:{name}"),"optional/development dependency absent from supplied installation".into());
                            } else {
                                return Err(error(
                                    DiagnosticCode::MissingDependency,
                                    format!(
                                        "installed dependency {name} is missing for package {dir}"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
        packages.insert(
            dir.clone(),
            PackageRecord {
                name: value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
                package_type: package_type.into(),
                main: value.get("main").and_then(Value::as_str).map(str::to_owned),
                exports: value.get("exports").cloned(),
                imports: value.get("imports").cloned(),
                dependencies,
            },
        );
    }
    let mut files = BTreeMap::new();
    for name in walk.files.keys() {
        let format = if name.ends_with(".mjs") {
            Some("module")
        } else if name.ends_with(".cjs") {
            Some("commonjs")
        } else if name.ends_with(".json") {
            Some("json")
        } else if name.ends_with(".js") {
            Some(
                packages
                    .iter()
                    .filter(|(dir, _)| dir.is_empty() || name.starts_with(&format!("{dir}/")))
                    .max_by_key(|(dir, _)| dir.len())
                    .map(|(_, p)| p.package_type.as_str())
                    .unwrap_or("commonjs"),
            )
        } else {
            None
        };
        if let Some(format) = format {
            files.insert(
                name.clone(),
                ModuleFile {
                    format: format.into(),
                    resource: Some(name.clone()),
                    deployed: None,
                    node_api: None,
                },
            );
        }
    }
    if !files.contains_key(&entry) {
        return Err(error(
            DiagnosticCode::MissingEntry,
            "entry was excluded from project inventory",
        ));
    }
    let native_addons = walk
        .native
        .iter()
        .filter(|(p, _)| p.ends_with(".node"))
        .map(|(p, s)| (p.clone(), s.clone()))
        .collect();
    let index = ModuleIndex {
        schema_version: 1,
        entry,
        files,
        packages,
    };
    let mut resources = walk.files;
    resources.insert(
        "module-index.json".into(),
        serde_json::to_vec(&index)
            .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?,
    );
    Ok(NodeProject {
        root: root.clone(),
        app_id,
        index,
        resources,
        native_addons,
        native_files: walk.native,
        omissions,
    })
}
/// Source-only adapter. Native addons are routed by N05, never silently omitted.
pub fn build(
    options: &NodeBuildOptions,
    launcher: &Path,
    output: &Path,
    limits: DistributionLimits,
) -> Result<glue_format::DistributionBuildReport> {
    let project = ingest(&options.project, options.entry.as_deref(), Some(output))?;
    if !project.native_addons.is_empty() {
        return Err(error(
            DiagnosticCode::UnsupportedCapability,
            "Node addon deployment requires the native addon adapter",
        ));
    }
    let discovered = glue_runtime_node::discover(&options.node, options.target.as_deref())?;
    let mut roots = vec![crate::native::NativeSearchRoot {
        source: discovered.executable.parent().unwrap().into(),
        deployed: "runtime".into(),
        provider: glue_format::DependencyProvider::Runtime,
    }];
    for (i, source) in options.native_search.iter().enumerate() {
        roots.push(crate::native::NativeSearchRoot {
            source: source.clone(),
            deployed: format!("runtime/dependencies/{i}"),
            provider: glue_format::DependencyProvider::Bundled,
        });
    }
    let native = if options.host {
        crate::native::NativeCollection::default()
    } else {
        crate::native::collect(&crate::native::NativeRequest {
            images: vec![discovered.executable.clone()],
            search_roots: roots,
            target: discovered.descriptor.target.clone(),
            normalize: options.normalize_native_paths,
            host_libraries: BTreeSet::new(),
        })?
    };
    let provider = glue_runtime_node::prepare(
        discovered,
        &options.bridge,
        BTreeMap::new(),
        native.inventory.clone(),
        options.host,
    )?;
    let mut payloads: BTreeMap<_, _> = provider
        .payloads
        .into_iter()
        .map(|(p, s)| {
            (
                p,
                match s {
                    glue_runtime_node::NodePayload::File(p) => PayloadSource::File(p),
                    glue_runtime_node::NodePayload::Bytes { bytes, mode } => {
                        PayloadSource::Bytes { bytes, mode }
                    }
                },
            )
        })
        .collect();
    payloads.extend(native.payloads);
    crate::distribution::build(DistributionInput{app_id:project.app_id,entrypoint:"module-index.json".into(),runtime:provider.runtime,launch:provider.launch,resources:project.resources,payloads,native:provider.native,omissions:project.omissions,notices:"Node runtime and supplied project dependencies retain their original licenses; packaged license files are archived with the project.\n".into(),options:BTreeMap::from([("language".into(),"node".into())])},launcher,output,limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "glue-node-project-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn put(&self, p: &str, b: &str) {
            let p = self.0.join(p);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, b).unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn npm_sources_assets_and_ordered_conditions() {
        let t = Temp::new();
        t.put("package.json",r##"{"name":"ordinary","main":"dist/main.js","dependencies":{"dep":"1"},"scripts":{"postinstall":"touch SHOULD_NOT_EXIST"}}"##);
        t.put("dist/main.js", "module.exports=require('dep')");
        t.put("asset.txt", "resource");
        t.put("package-lock.json", "{}");
        t.put("node_modules/dep/package.json",r##"{"name":"dep","type":"module","exports":{".":{"node":"./node.js","default":"./fallback.js"}}}"##);
        t.put("node_modules/dep/node.js", "export default 42");
        t.put("node_modules/dep/fallback.js", "export default 7");
        let p = ingest(&t.0, None, None).unwrap();
        assert_eq!(p.index.entry, "dist/main.js");
        assert_eq!(p.index.files["node_modules/dep/node.js"].format, "module");
        assert_eq!(p.index.packages[""].dependencies["dep"], "node_modules/dep");
        assert_eq!(p.resources["asset.txt"], b"resource");
        assert!(p.resources.contains_key("package-lock.json"));
        let raw = String::from_utf8(p.resources["module-index.json"].clone()).unwrap();
        assert!(raw.find("\"node\":").unwrap() < raw.find("\"default\":").unwrap());
        assert!(!t.0.join("SHOULD_NOT_EXIST").exists());
    }
    #[cfg(unix)]
    #[test]
    fn pnpm_internal_links_preserve_dependency_versions() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        t.put(
            "package.json",
            r#"{"name":"pnpm-app","main":"main.cjs","dependencies":{"a":"1","b":"2"}}"#,
        );
        t.put("main.cjs", "require('a');require('b')");
        for (name, version) in [("a", "1"), ("b", "2")] {
            let dir = format!("node_modules/.pnpm/{name}@{version}/node_modules/{name}");
            t.put(
                &format!("{dir}/package.json"),
                &format!(r#"{{"name":"{name}","main":"index.js"}}"#),
            );
            t.put(&format!("{dir}/index.js"), version);
            symlink(
                format!(".pnpm/{name}@{version}/node_modules/{name}"),
                t.0.join("node_modules").join(name),
            )
            .unwrap();
        }
        let p = ingest(&t.0, None, None).unwrap();
        assert_eq!(
            p.index.packages[""].dependencies["a"],
            "node_modules/.pnpm/a@1/node_modules/a"
        );
        assert_eq!(
            p.index.packages[""].dependencies["b"],
            "node_modules/.pnpm/b@2/node_modules/b"
        );
    }
    #[test]
    fn missing_dependencies_entries_and_pnp_diagnose() {
        let t = Temp::new();
        t.put("package.json", r#"{"dependencies":{"missing":"1"}}"#);
        assert_eq!(
            ingest(&t.0, None, None).unwrap_err().code,
            DiagnosticCode::MissingEntry
        );
        t.put("main.cjs", "");
        assert_eq!(
            ingest(&t.0, Some(Path::new("main.cjs")), None)
                .unwrap_err()
                .code,
            DiagnosticCode::MissingDependency
        );
        t.put(".pnp.cjs", "throw Error('never execute')");
        assert_eq!(
            ingest(&t.0, Some(Path::new("main.cjs")), None)
                .unwrap_err()
                .code,
            DiagnosticCode::UnsupportedCapability
        );
    }
    #[cfg(unix)]
    #[test]
    fn escaped_link_rejects_and_native_is_not_archived() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        t.put("package.json", r#"{"main":"main.js"}"#);
        t.put("main.js", "");
        t.put("addon.node", "preexisting native bytes");
        let p = ingest(&t.0, None, None).unwrap();
        assert!(p.native_addons.contains_key("addon.node"));
        assert!(!p.resources.contains_key("addon.node"));
        symlink("/etc/passwd", t.0.join("escaped")).unwrap();
        assert_eq!(
            ingest(&t.0, None, None).unwrap_err().code,
            DiagnosticCode::PathEscape
        );
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    #[test]
    fn npm_and_pnpm_build_and_run_after_input_removal() {
        let Some(bridge) = std::env::var_os("GLUE_NODE_TEST_BRIDGE") else {
            eprintln!("GLUE_NODE_TEST_BRIDGE unset; high-level Node execution test not run");
            return;
        };
        let node = std::env::var_os("GLUE_NODE_TEST_EXECUTABLE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin/node"));
        let base = std::env::temp_dir().join(format!("glue-node-build-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        for (name, pnpm, esm) in [("npm", false, false), ("pnpm", true, true)] {
            let source = base.join(name);
            fs::create_dir(&source).unwrap();
            fs::write(source.join("package.json"),format!(r#"{{"name":"{name}","type":"{}","main":"main.js","dependencies":{{"dep":"1"}},"scripts":{{"postinstall":"touch SHOULD_NOT_EXIST"}}}}"#,if esm{"module"}else{"commonjs"})).unwrap();
            fs::write(source.join("asset.txt"), b"preserved asset").unwrap();
            fs::write(source.join("main.js"),if esm{"import dep from 'dep';if(dep!==42||process.argv[2]!=='hello argument'||glueResources.read('asset.txt').toString()!=='preserved asset')throw Error('bad result');console.log('esm:42');"}else{"const dep=require('dep');if(dep!==42||process.argv[2]!=='hello argument'||glueResources.read('asset.txt').toString()!=='preserved asset')throw Error('bad result');console.log('cjs:42');"}).unwrap();
            let dep = source.join(if pnpm {
                "node_modules/.pnpm/dep@1/node_modules/dep"
            } else {
                "node_modules/dep"
            });
            fs::create_dir_all(&dep).unwrap();
            fs::write(
                dep.join("package.json"),
                r#"{"name":"dep","main":"index.js"}"#,
            )
            .unwrap();
            fs::write(dep.join("index.js"), "module.exports=42;").unwrap();
            #[cfg(unix)]
            if pnpm {
                std::os::unix::fs::symlink(
                    ".pnpm/dep@1/node_modules/dep",
                    source.join("node_modules/dep"),
                )
                .unwrap();
            }
            let output = base.join(format!("relocated {name} é"));
            let opts = NodeBuildOptions {
                project: source.clone(),
                entry: None,
                node: node.clone(),
                bridge: bridge.clone().into(),
                target: None,
                host: true,
                native_search: vec![],
                normalize_native_paths: false,
            };
            let report = build(
                &opts,
                &std::env::current_exe().unwrap(),
                &output,
                DistributionLimits::default(),
            )
            .unwrap();
            assert_eq!(report.runtime.provider, glue_format::RuntimeProvider::Host);
            assert!(!source.join("SHOULD_NOT_EXIST").exists());
            fs::remove_dir_all(source).unwrap();
            let result = std::process::Command::new(&node)
                .arg(output.join("support/node-bootstrap.cjs"))
                .arg(output.join("app.glue"))
                .arg(output.join("support/archive.node"))
                .arg("hello argument")
                .env_clear()
                .env("NODE_DISABLE_COMPILE_CACHE", "1")
                .env("PATH", "/no-tools")
                .env("HOME", "/no-home")
                .env("TMPDIR", "/no-temp")
                .current_dir(&base)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&result.stdout),
                if esm { "esm:42\n" } else { "cjs:42\n" }
            );
        }
        fs::remove_dir_all(base).unwrap();
    }
}
