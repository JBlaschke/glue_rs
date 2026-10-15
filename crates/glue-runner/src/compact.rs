//! Compact command dispatch. Adapters own discovery; this module owns launch and CLI policy.
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
    time::{Duration, Instant},
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
        return Some(build(&args[1..]));
    }
    if !["run", "doctor", "inspect", "explain-size"].contains(&command) {
        return None;
    }
    let path = args.get(1)?;
    if path == "--help" || path == "-h" {
        return None;
    }
    let file = File::open(path).ok()?;
    let archive = match Archive::open(file) {
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
// Adapter configuration becomes active when the Python/Node slots land in R01.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
fn build(args: &[OsString]) -> Result<ExitCode> {
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
            glue_pack::lua::build(&options, &launcher, &output, DistributionLimits::default())?
        }
        "python" | "node" => {
            let _ = (&c.python, &c.node, native_search, normalize, entry, mode);
            return Err(error(
                DiagnosticCode::UnsupportedCapability,
                format!("{language} compact adapter is not integrated in this task branch"),
            ));
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
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if spec.runtime.implementation == RuntimeImplementation::Lua {
        command.arg("--describe");
    } else {
        command.arg("--version");
    }
    let mut child = command
        .spawn()
        .map_err(|e| error(DiagnosticCode::RuntimeProcessFailure, e.to_string()))?;
    let stdout = child.stdout.take().unwrap();
    let handle = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(65537).read_to_end(&mut bytes).map(|_| bytes)
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(error(
                        DiagnosticCode::RuntimeAbiMismatch,
                        "runtime metadata probe failed",
                    ));
                }
                break;
            }
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(
                    DiagnosticCode::RuntimeProcessFailure,
                    "runtime metadata probe timed out",
                ));
            }
        }
    }
    let bytes = handle
        .join()
        .map_err(|_| {
            error(
                DiagnosticCode::RuntimeProcessFailure,
                "runtime probe reader failed",
            )
        })?
        .map_err(|e| error(DiagnosticCode::RuntimeProcessFailure, e.to_string()))?;
    if bytes.len() > 65536 {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "runtime probe output exceeds bound",
        ));
    }
    let version = if spec.runtime.implementation == RuntimeImplementation::Lua {
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, e.to_string()))?;
        format!(
            "{}.{}.{}",
            value["version"]["major"], value["version"]["minor"], value["version"]["patch"]
        )
    } else {
        String::from_utf8_lossy(&bytes)
            .trim()
            .trim_start_matches("Python ")
            .trim_start_matches('v')
            .to_owned()
    };
    if version != spec.runtime.version {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            format!(
                "selected runtime reports {version}, expected {}",
                spec.runtime.version
            ),
        ));
    }
    Ok(())
}
fn distribution_command(
    command: &str,
    path: &Path,
    archive: Archive<File>,
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
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
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
