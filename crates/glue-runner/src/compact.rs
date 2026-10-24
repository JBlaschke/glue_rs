//! Compact command dispatch. Adapters own discovery; this module owns launch and CLI policy.
mod host;

use glue_format::*;
use glue_pack::distribution::{DistributionLimits, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};
fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "check glue --help and the selected project/runtime inputs",
    )
}
fn text(value: &OsString) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| error(DiagnosticCode::InvalidConfiguration, "option must be UTF-8"))
}
fn host_target() -> Result<String> {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        "macos" => Ok(format!("{arch}-apple-darwin")),
        _ => Err(error(
            DiagnosticCode::UnsupportedCapability,
            "compact launch requires Linux or macOS",
        )),
    }
}
/// Return None only for an existing legacy command; never reinterpret schema zero.
pub fn handle(args: &[OsString]) -> Option<Result<ExitCode>> {
    let command = args.first()?.to_str()?;
    if command == "build"
        && args
            .get(1)
            .is_some_and(|s| ["lua", "python", "node"].iter().any(|n| s == n))
    {
        return Some(build(&args[1..], None));
    }
    if command == "rebuild" {
        return Some(rebuild(&args[1..]));
    }
    if !["run", "doctor", "inspect", "explain-size"].contains(&command) {
        return None;
    }
    let path = args.get(1)?;
    if path == "--help" || path == "-h" {
        return None;
    }
    let file = File::open(path).ok()?;
    let archive = match Archive::open(BufferedReader::new(file)) {
        Ok(a) => a,
        Err(_) => return None,
    };
    if archive.manifest().schema_version != DISTRIBUTION_SCHEMA_VERSION {
        return None;
    }
    Some(distribution_command(
        command,
        Path::new(path),
        archive,
        &args[2..],
    ))
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Config {
    output: Option<PathBuf>,
    entry: Option<String>,
    target: Option<String>,
    delivery: Option<String>,
    runtime_mode: Option<String>,
    #[serde(default)]
    native_search: Vec<PathBuf>,
    #[serde(default)]
    normalize_native_paths: bool,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    lua: LuaConfig,
    #[serde(default)]
    python: PythonConfig,
    #[serde(default)]
    node: NodeConfig,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LuaConfig {
    version: Option<String>,
    helper_dir: Option<PathBuf>,
    rocks_tree: Option<PathBuf>,
    #[serde(default)]
    native_abi: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct PythonConfig {
    environment: Option<PathBuf>,
    project: Option<PathBuf>,
    runtime: Option<PathBuf>,
    version: Option<String>,
    module: Option<String>,
    console_script: Option<String>,
    #[serde(default)]
    prune: Vec<String>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct NodeConfig {
    executable: Option<PathBuf>,
    bridge: Option<PathBuf>,
    version: Option<String>,
}
#[derive(Default)]
struct Options {
    values: BTreeMap<String, OsString>,
    lists: BTreeMap<String, Vec<OsString>>,
    flags: BTreeSet<String>,
    project: Option<PathBuf>,
}
impl Options {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.values
            .get(key)
            .map(|v| text(v).map(str::to_owned))
            .transpose()
    }
    fn path(&self, key: &str) -> Option<PathBuf> {
        self.values.get(key).map(PathBuf::from)
    }
    fn list(&self, key: &str) -> Result<Vec<String>> {
        self.lists
            .get(key)
            .into_iter()
            .flatten()
            .map(|v| text(v).map(str::to_owned))
            .collect()
    }
}
fn parse(args: &[OsString]) -> Result<Options> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let arg = text(&args[i])?;
        if arg.starts_with("--") {
            if ["--json", "--normalize-native-paths"].contains(&arg) {
                if !o.flags.insert(arg.into()) {
                    return Err(error(
                        DiagnosticCode::InvalidConfiguration,
                        format!("duplicate {arg}"),
                    ));
                }
                i += 1;
                continue;
            }
            if ![
                "--output",
                "--entry",
                "--target",
                "--delivery",
                "--runtime-mode",
                "--config",
                "--lua",
                "--helper-dir",
                "--rocks-tree",
                "--env",
                "--project",
                "--runtime",
                "--python",
                "--module",
                "--console-script",
                "--node",
                "--node-version",
                "--node-bridge",
                "--native-search",
                "--native-abi",
                "--exclude",
                "--prune",
            ]
            .contains(&arg)
            {
                return Err(error(
                    DiagnosticCode::InvalidConfiguration,
                    format!("unknown option {arg}"),
                ));
            }
            let value = args
                .get(i + 1)
                .ok_or_else(|| {
                    error(
                        DiagnosticCode::InvalidConfiguration,
                        format!("missing value for {arg}"),
                    )
                })?
                .clone();
            if ["--native-search", "--native-abi", "--exclude", "--prune"].contains(&arg) {
                o.lists.entry(arg.into()).or_default().push(value);
            } else if o.values.insert(arg.into(), value).is_some() {
                return Err(error(
                    DiagnosticCode::InvalidConfiguration,
                    format!("duplicate {arg}"),
                ));
            }
            i += 2;
        } else {
            if o.project.replace(PathBuf::from(&args[i])).is_some() {
                return Err(error(
                    DiagnosticCode::InvalidConfiguration,
                    "multiple project paths",
                ));
            }
            i += 1;
        }
    }
    Ok(o)
}
fn config(options: &Options, project: &Path) -> Result<Config> {
    let path = options
        .path("--config")
        .unwrap_or_else(|| project.join("glue.toml"));
    if !path.exists() && options.path("--config").is_none() {
        return Ok(Config::default());
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .and_then(|f| f.take(65537).read_to_end(&mut bytes))
        .map_err(|e| {
            error(
                DiagnosticCode::MissingInput,
                format!("{}: {e}", path.display()),
            )
        })?;
    if bytes.len() > 64 * 1024 {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "config exceeds 64 KiB",
        ));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    let mut c: Config = toml::from_str(content).map_err(|e| {
        error(
            DiagnosticCode::InvalidConfiguration,
            format!("{}: {e}", path.display()),
        )
    })?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let resolve = |p: &mut Option<PathBuf>| {
        if let Some(value) = p {
            if value.is_relative() {
                *value = parent.join(&*value);
            }
        }
    };
    resolve(&mut c.output);
    resolve(&mut c.lua.helper_dir);
    resolve(&mut c.lua.rocks_tree);
    resolve(&mut c.python.environment);
    resolve(&mut c.python.project);
    resolve(&mut c.python.runtime);
    resolve(&mut c.node.executable);
    resolve(&mut c.node.bridge);
    for p in &mut c.native_search {
        if p.is_relative() {
            *p = parent.join(&*p);
        }
    }
    Ok(c)
}
fn build(args: &[OsString], expected: Option<&RuntimeDescriptor>) -> Result<ExitCode> {
    let language = text(&args[0])?;
    let o = parse(&args[1..])?;
    let cwd =
        std::env::current_dir().map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let project = o
        .project
        .clone()
        .or_else(|| o.path("--project"))
        .unwrap_or(cwd);
    let c = config(&o, &project)?;
    validate_language_options(language, &o)?;
    let mut context = BTreeMap::from([
        (
            "glue.cli.argv".to_owned(),
            serde_json::to_string(&rebuild_arguments(args))
                .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?,
        ),
        (
            "glue.cli.cwd".to_owned(),
            std::env::current_dir()
                .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    if let Some(expected) = expected {
        context.insert(
            "glue.expected-runtime".into(),
            serde_json::to_string(expected).unwrap(),
        );
    }
    let delivery = o
        .get("--delivery")?
        .or(c.delivery.clone())
        .unwrap_or("compact".into());
    if delivery != "compact" {
        return Err(error(
            DiagnosticCode::UnsupportedMode,
            format!("delivery {delivery:?} has no proven high-level provider; select compact"),
        ));
    }
    let mode = o
        .get("--runtime-mode")?
        .or(c.runtime_mode.clone())
        .unwrap_or("bundled".into());
    if !["bundled", "host"].contains(&mode.as_str()) {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "runtime-mode must be bundled or host",
        ));
    }
    let output = o.path("--output").or(c.output.clone()).ok_or_else(|| {
        error(
            DiagnosticCode::InvalidConfiguration,
            "--output DIR is required",
        )
    })?;
    let target = o
        .get("--target")?
        .or(c.target.clone())
        .unwrap_or(host_target()?);
    if target != host_target()? {
        return Err(error(
            DiagnosticCode::TargetMismatch,
            "high-level builders execute only on the selected native target; use inspection for foreign inputs",
        ));
    }
    let entry = o.get("--entry")?.or(c.entry.clone());
    let launcher =
        std::env::current_exe().map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let mut native_search = c.native_search.clone();
    native_search.extend(o.list("--native-search")?.into_iter().map(PathBuf::from));
    let normalize = o.flags.contains("--normalize-native-paths") || c.normalize_native_paths;
    let report = match language {
        "lua" => {
            if mode != "bundled" {
                return Err(error(
                    DiagnosticCode::UnsupportedCapability,
                    "Lua uses its selected bundled helper",
                ));
            }
            let family: glue_runtime_lua::helper::LuaFamily = o
                .get("--lua")?
                .or(c.lua.version)
                .unwrap_or("5.4".into())
                .parse()
                .map_err(|e: glue_runtime_lua::helper::HelperError| {
                    error(DiagnosticCode::RuntimeAbiMismatch, e.to_string())
                })?;
            let mut directories = Vec::new();
            if let Some(dir) = o.path("--helper-dir").or(c.lua.helper_dir) {
                directories.push(dir);
            }
            if let Some(dir) = std::env::var_os("GLUE_HELPER_DIR") {
                directories.push(dir.into());
            }
            directories.push(launcher.parent().unwrap().to_owned());
            let helper=glue_runtime_lua::helper::discover(family,&target,&directories).map_err(|e|error(DiagnosticCode::MissingDependency,format!("{e}; install both helpers with scripts/install-lua-helpers.sh PREFIX, or use --helper-dir")))?;
            let executable = format!("runtime/{}", family.executable_name());
            let runtime = helper.descriptor.runtime_descriptor(
                executable,
                InputIdentity {
                    size: helper.size,
                    sha256: helper.sha256,
                },
            );
            let mut native_abis = c.lua.native_abi;
            for declaration in o.list("--native-abi")? {
                let (path, abi) = declaration.split_once('=').ok_or_else(|| {
                    error(
                        DiagnosticCode::InvalidConfiguration,
                        "--native-abi requires logical-path=5.4|5.5",
                    )
                })?;
                if native_abis.insert(path.into(), abi.into()).is_some() {
                    return Err(error(
                        DiagnosticCode::InvalidConfiguration,
                        "duplicate native ABI declaration",
                    ));
                }
            }
            let mut exclusions = c.exclude;
            exclusions.extend(o.list("--exclude")?);
            let options = glue_pack::lua::LuaProjectOptions {
                project,
                entry,
                rocks_tree: o.path("--rocks-tree").or(c.lua.rocks_tree),
                output: Some(output.clone()),
                runtime,
                helper_executable: helper.executable,
                exclusions,
                native_abis,
                native_search,
                normalize_native_paths: normalize,
            };
            let limits = DistributionLimits::default();
            let mut input = glue_pack::lua::ingest(&options, limits)?;
            glue_pack::lua::resolve_native(&options, &mut input)?;
            publish(input, &launcher, &output, context)?
        }
        "python" => {
            use glue_pack::python::{
                compact,
                discovery::DiscoveryOptions,
                inventory::{InventoryOptions, PythonEntry},
            };
            let has_cli_entry = ["--entry", "--module", "--console-script"]
                .iter()
                .any(|k| o.values.contains_key(*k));
            let selected = if has_cli_entry {
                [
                    o.get("--entry")?.map(PythonEntry::File),
                    o.get("--module")?.map(PythonEntry::Module),
                    o.get("--console-script")?.map(PythonEntry::ConsoleScript),
                ]
            } else {
                [
                    entry.map(PythonEntry::File),
                    c.python.module.map(PythonEntry::Module),
                    c.python.console_script.map(PythonEntry::ConsoleScript),
                ]
            };
            let mut selected: Vec<_> = selected.into_iter().flatten().collect();
            if selected.len() != 1 {
                return Err(error(
                    DiagnosticCode::MissingEntry,
                    "select exactly one --entry FILE, --module NAME or --console-script NAME (or one configured entry)",
                ));
            }
            let project = o.path("--project").or(c.python.project).unwrap_or(project);
            let environment = o
                .path("--env")
                .or(c.python.environment)
                .unwrap_or_else(|| project.join(".venv"));
            let mut application = InventoryOptions::new(project.clone(), selected.remove(0));
            application.output = Some(output.clone());
            application.prune.extend(c.python.prune);
            application.prune.extend(o.list("--prune")?);
            let options = compact::CompactBuildOptions {
                discovery: DiscoveryOptions {
                    environment,
                    runtime: o.path("--runtime").or(c.python.runtime),
                    python_version: o.get("--python")?.or(c.python.version),
                    target: Some(target),
                    inspect_only: false,
                },
                application,
                runtime_provider: if mode == "host" {
                    RuntimeProvider::Host
                } else {
                    RuntimeProvider::Bundled
                },
                native_search,
                normalize_native_paths: normalize,
                app_id: project
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("python-application")
                    .to_owned(),
            };
            compact::build_with_options(&options, &launcher, &output, &context)?
        }
        "node" => {
            let node=o.path("--node").or(c.node.executable).ok_or_else(||error(DiagnosticCode::MissingInput,"--node EXECUTABLE or node.executable in glue.toml is required; no runtime is downloaded"))?;
            if let Some(constraint) = o.get("--node-version")?.or(c.node.version) {
                let selected = glue_runtime_node::discover(&node, Some(&target))?;
                require_node_version(&selected.descriptor.version, &constraint)?;
            }
            let bridge = o
                .path("--node-bridge")
                .or(c.node.bridge)
                .or_else(|| std::env::var_os("GLUE_NODE_BRIDGE").map(PathBuf::from))
                .unwrap_or_else(|| launcher.parent().unwrap().join("glue-archive.node"));
            let options = glue_pack::node::NodeBuildOptions {
                project,
                entry: entry.map(PathBuf::from),
                node,
                bridge,
                target: Some(target),
                host: mode == "host",
                native_search,
                normalize_native_paths: normalize,
            };
            let input = glue_pack::node::prepare(&options, &output, DistributionLimits::default())?;
            publish(input, &launcher, &output, context)?
        }
        _ => unreachable!(),
    };
    if o.flags.contains("--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?
        );
    } else {
        println!(
            "built {} ({} deployed files, {} archive bytes)",
            output.display(),
            report.sizes.deployed_files,
            report.sizes.archive_bytes
        );
    }
    Ok(ExitCode::SUCCESS)
}
fn verify_payloads(root: &Path, spec: &DistributionSpec) -> Result<()> {
    for (path, payload) in &spec.payloads {
        let file = root.join(path);
        let meta = fs::symlink_metadata(&file).map_err(|e| {
            error(
                DiagnosticCode::MissingDependency,
                format!("{}: {e}", file.display()),
            )
        })?;
        let resolved = fs::canonicalize(&file).map_err(|e| {
            error(
                DiagnosticCode::MissingDependency,
                format!("{}: {e}", file.display()),
            )
        })?;
        if !resolved.starts_with(root) {
            return Err(error(
                DiagnosticCode::PathEscape,
                format!("payload {path} escaped the distribution"),
            ));
        }
        let identity = match &payload.kind {
            PayloadKind::Symlink { target } => {
                if !meta.file_type().is_symlink()
                    || fs::read_link(&file)
                        .map_err(|e| error(DiagnosticCode::PayloadIntegrity, e.to_string()))?
                        != Path::new(target)
                {
                    return Err(error(
                        DiagnosticCode::PayloadIntegrity,
                        format!("payload link changed: {path}"),
                    ));
                }
                InputIdentity::of(target.as_bytes())
            }
            PayloadKind::File => {
                if !meta.is_file() || meta.len() != payload.size {
                    return Err(error(
                        DiagnosticCode::PayloadIntegrity,
                        format!("payload size/type changed: {path}"),
                    ));
                }
                let mut stream = File::open(&file)
                    .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
                let mut hash = Sha256::new();
                let mut bytes = [0u8; 65536];
                let mut total = 0u64;
                loop {
                    let n = stream
                        .read(&mut bytes)
                        .map_err(|e| error(DiagnosticCode::PayloadIntegrity, e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    total = total.checked_add(n as u64).ok_or_else(|| {
                        error(DiagnosticCode::ResourceLimit, "payload size overflow")
                    })?;
                    if total > payload.size {
                        return Err(error(
                            DiagnosticCode::PayloadIntegrity,
                            format!("payload grew: {path}"),
                        ));
                    }
                    hash.update(&bytes[..n]);
                }
                InputIdentity {
                    size: total,
                    sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
                }
            }
        };
        if identity.size != payload.size || identity.sha256 != payload.sha256 {
            return Err(error(
                DiagnosticCode::PayloadIntegrity,
                format!("payload hash changed: {path}"),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if matches!(payload.kind, PayloadKind::File)
                && ((meta.permissions().mode() & 0o555) != (payload.mode & 0o555)
                    || (meta.permissions().mode() & 0o222 & !payload.mode) != 0)
            {
                return Err(error(
                    DiagnosticCode::PayloadIntegrity,
                    format!("payload mode changed: {path}"),
                ));
            }
        }
    }
    Ok(())
}
fn selected_executable(root: &Path, spec: &DistributionSpec) -> Result<PathBuf> {
    match spec.runtime.provider {
        RuntimeProvider::Bundled => Ok(root.join(&spec.runtime.executable)),
        RuntimeProvider::Host => {
            let p = PathBuf::from(&spec.runtime.executable);
            if !p.is_file() {
                return Err(error(
                    DiagnosticCode::MissingDependency,
                    "declared host runtime is missing",
                ));
            }
            let key = match spec.runtime.implementation {
                RuntimeImplementation::Node => "node-executable",
                RuntimeImplementation::Cpython => "runtime-executable",
                RuntimeImplementation::Lua => "helper-executable",
            };
            let expected = spec.runtime.inputs.get(key).ok_or_else(|| {
                error(
                    DiagnosticCode::InvalidConfiguration,
                    "host runtime executable identity is missing",
                )
            })?;
            let mut stream = File::open(&p)
                .map_err(|e| error(DiagnosticCode::MissingDependency, e.to_string()))?;
            let mut hash = Sha256::new();
            let mut bytes = [0u8; 65536];
            let mut total = 0u64;
            loop {
                let n = stream
                    .read(&mut bytes)
                    .map_err(|e| error(DiagnosticCode::PayloadIntegrity, e.to_string()))?;
                if n == 0 {
                    break;
                }
                total = total.checked_add(n as u64).ok_or_else(|| {
                    error(DiagnosticCode::ResourceLimit, "host runtime size overflow")
                })?;
                if total > expected.size {
                    return Err(error(
                        DiagnosticCode::RuntimeAbiMismatch,
                        "host runtime executable changed",
                    ));
                }
                hash.update(&bytes[..n]);
            }
            let actual = InputIdentity {
                size: total,
                sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
            };
            if &actual != expected {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    "host runtime executable changed",
                ));
            }
            Ok(p)
        }
    }
}
fn substitute(value: &str, root: &Path, archive: &Path) -> Result<String> {
    let r = root.to_str().ok_or_else(|| {
        error(
            DiagnosticCode::PathEscape,
            "distribution path must be UTF-8",
        )
    })?;
    let a = archive
        .to_str()
        .ok_or_else(|| error(DiagnosticCode::PathEscape, "archive path must be UTF-8"))?;
    let mut result = String::new();
    let mut remaining = value;
    while let Some(i) = remaining.find('{') {
        result.push_str(&remaining[..i]);
        remaining = &remaining[i..];
        if let Some(tail) = remaining.strip_prefix("{root}") {
            result.push_str(r);
            remaining = tail;
        } else if let Some(tail) = remaining.strip_prefix("{archive}") {
            result.push_str(a);
            remaining = tail;
        } else {
            result.push('{');
            remaining = &remaining[1..];
        }
    }
    result.push_str(remaining);
    Ok(result)
}
fn runtime_probe(executable: &Path, spec: &DistributionSpec) -> Result<()> {
    match spec.runtime.implementation {
        RuntimeImplementation::Lua => {
            let helper = glue_runtime_lua::helper::query(executable)
                .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, e.to_string()))?;
            let RuntimeAbi::Lua { version, .. } = &spec.runtime.abi else {
                unreachable!()
            };
            let family = if version.minor == 4 {
                glue_runtime_lua::helper::LuaFamily::Lua54
            } else {
                glue_runtime_lua::helper::LuaFamily::Lua55
            };
            helper
                .validate(family, &spec.runtime.target)
                .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, e.to_string()))?;
            let actual = helper.runtime_descriptor(
                spec.runtime.executable.clone(),
                InputIdentity {
                    size: 0,
                    sha256: digest(b""),
                },
            );
            if actual.abi != spec.runtime.abi || actual.version != spec.runtime.version {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    "Lua helper differs from declared ABI",
                ));
            }
        }
        RuntimeImplementation::Node => {
            let actual = glue_runtime_node::discover(executable, Some(&spec.runtime.target))?;
            if actual.descriptor.version != spec.runtime.version
                || actual.descriptor.abi != spec.runtime.abi
            {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    "Node executable differs from declared version/ABI/capabilities",
                ));
            }
        }
        RuntimeImplementation::Cpython => {
            let actual = glue_pack::python::discovery::probe(executable, Duration::from_secs(5))
                .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, e))?;
            validate_python_probe(&actual, &spec.runtime)?;
        }
    }
    Ok(())
}

fn validate_python_probe(
    actual: &glue_pack::python::discovery::RuntimeMetadata,
    runtime: &RuntimeDescriptor,
) -> Result<()> {
    let RuntimeAbi::Python {
        version,
        gil,
        debug,
    } = &runtime.abi
    else {
        unreachable!()
    };
    // Discovery records the exact version token, not sys.version's build banner.
    // Keep prerelease suffixes: the numeric ABI version alone cannot distinguish them.
    if actual.implementation != "cpython"
        || actual.version != [version.major, version.minor, version.patch]
        || actual.version_text.split_whitespace().next() != Some(runtime.version.as_str())
        || actual.debug != *debug
        || actual.gil_disabled != (*gil == GilMode::FreeThreaded)
    {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            "Python executable differs from declared exact version/ABI",
        ));
    }
    Ok(())
}

fn distribution_command(
    command: &str,
    path: &Path,
    archive: Archive<BufferedReader<File>>,
    args: &[OsString],
) -> Result<ExitCode> {
    let m = archive.manifest();
    let spec = m.distribution.as_ref().expect("validated schema one");
    let json = args.iter().any(|a| a == "--json");
    if ["inspect", "explain-size", "doctor"].contains(&command)
        && args.iter().any(|a| a != "--json")
    {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "unexpected command argument",
        ));
    }
    if command == "inspect" {
        if json {
            println!(
                "{}",
                String::from_utf8(
                    m.to_json()
                        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?
                )
                .unwrap()
            );
        } else {
            println!(
                "{}: {:?} {:?} {} ({})\n{} archived resources, {} deployed payloads",
                m.app_id,
                spec.delivery,
                spec.runtime.implementation,
                spec.runtime.version,
                spec.runtime.target,
                m.resources.len(),
                spec.payloads.len()
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    if command == "explain-size" {
        let mut archived: Vec<_> = m
            .resources
            .iter()
            .map(|(p, r)| (r.size, p.as_str(), "archive"))
            .collect();
        archived.extend(
            spec.payloads
                .iter()
                .map(|(p, r)| (r.size, p.as_str(), "deployed")),
        );
        archived.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        if json {
            println!("{}", serde_json::to_string(&archived).unwrap());
        } else {
            for (size, name, kind) in archived.into_iter().take(30) {
                println!("{size:>12} {kind:>8} {name}");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    if spec.delivery != DeliveryMode::Compact {
        return Err(error(
            DiagnosticCode::UnsupportedMode,
            "memory delivery cannot use the compact launcher",
        ));
    }
    if spec.runtime.target != host_target()? {
        return Err(error(
            DiagnosticCode::TargetMismatch,
            format!(
                "distribution is for {}, this host is {}",
                spec.runtime.target,
                host_target()?
            ),
        ));
    }
    let path =
        fs::canonicalize(path).map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let root = path.parent().unwrap();
    verify_payloads(root, spec)?;
    host::check(spec)?;
    let executable = selected_executable(root, spec)?;
    if command == "doctor" {
        runtime_probe(&executable, spec)?;
        if json {
            println!(
                "{}",
                serde_json::json!({"status":"ok","delivery":"compact","runtime":spec.runtime,"payloads_verified":spec.payloads.len(),"application_executed":false})
            );
        } else {
            println!(
                "compact distribution verified; {:?} {} ({})",
                spec.runtime.implementation, spec.runtime.version, spec.runtime.target
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut app_args = args;
    if let Some(a) = app_args.first() {
        if a != "--" {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                "application arguments must follow --",
            ));
        }
        app_args = &app_args[1..];
    }
    let mut launch = Command::new(executable);
    if spec.launch.clear_environment {
        launch.env_clear();
    }
    for variable in [
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_COMPILE_CACHE",
        "LUA_INIT",
        "LUA_INIT_5_4",
        "LUA_INIT_5_5",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_PROFILE",
        "LD_PROFILE_OUTPUT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
    ] {
        launch.env_remove(variable);
    }
    for arg in &spec.launch.args {
        launch.arg(substitute(arg, root, &path)?);
    }
    for (key, value) in &spec.launch.environment {
        launch.env(key, substitute(value, root, &path)?);
    }
    launch
        .args(app_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    drop(archive);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(error(
            DiagnosticCode::RuntimeProcessFailure,
            launch.exec().to_string(),
        ))
    }
    #[cfg(not(unix))]
    {
        let status = launch
            .status()
            .map_err(|e| error(DiagnosticCode::RuntimeProcessFailure, e.to_string()))?;
        Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
    }
}

fn validate_language_options(language: &str, o: &Options) -> Result<()> {
    let groups = [
        (
            "lua",
            vec![
                "--lua",
                "--helper-dir",
                "--rocks-tree",
                "--native-abi",
                "--exclude",
            ],
        ),
        (
            "python",
            vec![
                "--env",
                "--project",
                "--runtime",
                "--python",
                "--module",
                "--console-script",
                "--prune",
            ],
        ),
        ("node", vec!["--node", "--node-version", "--node-bridge"]),
    ];
    for (owner, keys) in groups {
        if owner != language {
            for key in keys {
                if o.values.contains_key(key) || o.lists.contains_key(key) {
                    return Err(error(
                        DiagnosticCode::InvalidConfiguration,
                        format!("{key} is a {owner} option, not valid for {language}"),
                    ));
                }
            }
        }
    }
    Ok(())
}
fn runtime_matches(expected: &RuntimeDescriptor, actual: &RuntimeDescriptor) -> bool {
    expected.implementation == actual.implementation
        && expected.version == actual.version
        && expected.abi == actual.abi
        && expected.target == actual.target
        && expected.provider == actual.provider
        && expected.inputs == actual.inputs
}
fn publish(
    mut input: glue_pack::distribution::DistributionInput,
    launcher: &Path,
    output: &Path,
    mut context: BTreeMap<String, String>,
) -> Result<DistributionBuildReport> {
    if let Some(expected) = context.remove("glue.expected-runtime") {
        let expected: RuntimeDescriptor = serde_json::from_str(&expected)
            .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
        if !runtime_matches(&expected, &input.runtime) {
            return Err(error(
                DiagnosticCode::PayloadIntegrity,
                "selected runtime differs from recorded rebuild lock",
            ));
        }
    }
    input.options.extend(context);
    glue_pack::distribution::build(input, launcher, output, DistributionLimits::default())
}
fn require_node_version(version: &str, constraint: &str) -> Result<()> {
    let version = semver::Version::parse(version)
        .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, e.to_string()))?;
    for alternative in constraint.split("||") {
        let normalized = alternative
            .split_whitespace()
            .map(|s| s.trim_end_matches(','))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        let request = semver::VersionReq::parse(&normalized).map_err(|e| {
            error(
                DiagnosticCode::InvalidConfiguration,
                format!("invalid Node version constraint {constraint:?}: {e}"),
            )
        })?;
        if request.matches(&version) {
            return Ok(());
        }
    }
    Err(error(
        DiagnosticCode::RuntimeAbiMismatch,
        format!("selected Node {version} does not satisfy {constraint}"),
    ))
}
fn rebuild_arguments(args: &[OsString]) -> Vec<String> {
    let mut output = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--output" {
            i += 2;
            continue;
        }
        if args[i] != "--json" {
            output.push(args[i].to_string_lossy().into_owned());
        }
        i += 1;
    }
    output
}
fn rebuild(args: &[OsString]) -> Result<ExitCode> {
    let lock_path = args.first().ok_or_else(|| {
        error(
            DiagnosticCode::MissingInput,
            "rebuild requires glue.lock.json",
        )
    })?;
    let overrides = parse(&args[1..])?;
    if overrides.project.is_some() {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "use --project for a rebuild project override",
        ));
    }
    let mut bytes = Vec::new();
    File::open(lock_path)
        .and_then(|f| {
            f.take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "rebuild lock exceeds bound",
        ));
    }
    let lock: BuildLock = serde_json::from_slice(&bytes)
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    if lock.revision != 1 {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "unsupported rebuild lock revision",
        ));
    }
    let recorded: Vec<String> =
        serde_json::from_str(lock.options.get("glue.cli.argv").ok_or_else(|| {
            error(
                DiagnosticCode::UnsupportedCapability,
                "lock has no recorded high-level CLI; use the original config",
            )
        })?)
        .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
    let language = recorded
        .first()
        .filter(|s| ["lua", "python", "node"].contains(&s.as_str()))
        .ok_or_else(|| {
            error(
                DiagnosticCode::InvalidConfiguration,
                "invalid recorded language",
            )
        })?;
    let recorded_args: Vec<OsString> = recorded.iter().map(OsString::from).collect();
    let mut options = parse(&recorded_args[1..])?;
    let caller =
        std::env::current_dir().map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let output = overrides.path("--output").ok_or_else(|| {
        error(
            DiagnosticCode::InvalidConfiguration,
            "rebuild requires a new --output DIR",
        )
    })?;
    let output = if output.is_absolute() {
        output
    } else {
        caller.join(output)
    };
    if let Some(project) = overrides.path("--project") {
        options.project = Some(if project.is_absolute() {
            project
        } else {
            caller.join(project)
        });
    }
    for (key, value) in overrides.values {
        if key != "--output" && (key != "--project" || language == "python") {
            options.values.insert(key, value);
        }
    }
    options
        .values
        .insert("--output".into(), output.into_os_string());
    options.lists.extend(overrides.lists);
    options.flags.extend(overrides.flags);
    let cwd = lock.options.get("glue.cli.cwd").ok_or_else(|| {
        error(
            DiagnosticCode::InvalidConfiguration,
            "rebuild cwd is missing",
        )
    })?;
    std::env::set_current_dir(cwd).map_err(|e| {
        error(
            DiagnosticCode::MissingInput,
            format!("recorded source working directory {cwd}: {e}"),
        )
    })?;
    let mut argv = vec![OsString::from(language)];
    if let Some(project) = options.project {
        argv.push(project.into_os_string());
    }
    for (key, value) in options.values {
        argv.push(key.into());
        argv.push(value);
    }
    for (key, values) in options.lists {
        for value in values {
            argv.push(key.clone().into());
            argv.push(value);
        }
    }
    for flag in options.flags {
        argv.push(flag.into());
    }
    build(&argv, Some(&lock.runtime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use glue_pack::python::discovery::RuntimeMetadata;

    fn python_probe_fixture() -> (RuntimeMetadata, RuntimeDescriptor) {
        let actual = RuntimeMetadata {
            executable: "/runtime/bin/python3.14".into(),
            prefix: "/runtime".into(),
            stdlib: "/runtime/lib/python3.14".into(),
            version: [3, 14, 5],
            version_text: "3.14.5 (main, May 5 2026, 12:00:00)\n[Clang 18.1.8]".into(),
            implementation: "cpython".into(),
            machine: "arm64".into(),
            system: "Darwin".into(),
            soabi: "cpython-314-darwin".into(),
            gil_disabled: false,
            debug: false,
            framework: String::new(),
            extension_suffixes: vec![".cpython-314-darwin.so".into()],
        };
        let runtime = RuntimeDescriptor {
            implementation: RuntimeImplementation::Cpython,
            version: "3.14.5".into(),
            target: "aarch64-apple-darwin".into(),
            abi: RuntimeAbi::Python {
                version: RuntimeVersion {
                    major: 3,
                    minor: 14,
                    patch: 5,
                },
                gil: GilMode::Conventional,
                debug: false,
            },
            provider: RuntimeProvider::Bundled,
            executable: "runtime/bin/python3.14".into(),
            inputs: BTreeMap::new(),
            requirements: BTreeSet::new(),
        };
        (actual, runtime)
    }

    #[test]
    fn python_probe_accepts_full_build_banner_and_matching_prerelease() {
        let (mut actual, mut runtime) = python_probe_fixture();
        validate_python_probe(&actual, &runtime).unwrap();
        actual.version_text = "3.14.5".into();
        validate_python_probe(&actual, &runtime).unwrap();

        actual.version = [3, 15, 0];
        actual.version_text = "3.15.0rc1 (main, Oct 1 2026, 12:00:00) [GCC 14.2.0]".into();
        runtime.version = "3.15.0rc1".into();
        let RuntimeAbi::Python { version, .. } = &mut runtime.abi else {
            unreachable!()
        };
        version.minor = 15;
        version.patch = 0;
        validate_python_probe(&actual, &runtime).unwrap();

        for text in ["3.15.0rc2 (main, build)", "3.15.0 (main, build)"] {
            actual.version_text = text.into();
            assert_eq!(
                validate_python_probe(&actual, &runtime).unwrap_err().code,
                DiagnosticCode::RuntimeAbiMismatch,
                "must preserve the exact prerelease token: {text}",
            );
        }
    }

    #[test]
    fn python_probe_rejects_wrong_patch_and_numeric_abi() {
        let (mut actual, runtime) = python_probe_fixture();
        for text in ["3.14.6 (main, build)", "3.14.5rc1 (main, build)", ""] {
            actual.version_text = text.into();
            assert_eq!(
                validate_python_probe(&actual, &runtime).unwrap_err().code,
                DiagnosticCode::RuntimeAbiMismatch,
                "must reject a different or missing exact version: {text:?}",
            );
        }
        actual.version_text = "3.14.5 (main, build)".into();
        actual.version[2] = 6;
        assert_eq!(
            validate_python_probe(&actual, &runtime).unwrap_err().code,
            DiagnosticCode::RuntimeAbiMismatch,
        );
    }

    #[test]
    fn python_probe_rejects_debug_gil_and_implementation_changes() {
        let (actual, runtime) = python_probe_fixture();
        let mut debug = actual.clone();
        debug.debug = true;
        let mut free_threaded = actual.clone();
        free_threaded.gil_disabled = true;
        let mut different_implementation = actual;
        different_implementation.implementation = "pypy".into();
        for changed in [debug, free_threaded, different_implementation] {
            assert_eq!(
                validate_python_probe(&changed, &runtime).unwrap_err().code,
                DiagnosticCode::RuntimeAbiMismatch,
            );
        }
    }
}
