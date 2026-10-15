use glue_format::{
    Diagnostic, DiagnosticCode, InputIdentity, NativeInventory, RuntimeAbi, RuntimeDescriptor,
    RuntimeImplementation, RuntimeLaunchSpec, RuntimeProvider, RuntimeVersion,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Diagnostic>;
fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "select a compatible stock Node executable and a matching glue archive bridge",
    )
}
#[derive(Debug, Clone)]
pub struct DiscoveredNode {
    pub executable: PathBuf,
    pub descriptor: RuntimeDescriptor,
}
#[derive(Debug, Clone)]
pub enum NodePayload {
    File(PathBuf),
    Bytes { bytes: Vec<u8>, mode: u32 },
}
#[derive(Debug, Clone)]
pub struct NodeProvider {
    pub runtime: RuntimeDescriptor,
    pub launch: RuntimeLaunchSpec,
    pub payloads: BTreeMap<String, NodePayload>,
    pub native: NativeInventory,
}
#[derive(Deserialize)]
struct Probe {
    version: String,
    platform: String,
    arch: String,
    node_api: u32,
    addon_abi: u32,
    hooks: bool,
}
const PROBE: &str = "JSON.stringify({version:process.versions.node,platform:process.platform,arch:process.arch,node_api:Number(process.versions.napi||0),addon_abi:Number(process.versions.modules||0),hooks:typeof require('node:module').registerHooks==='function'})";

/// Probe only Node builtins, with no project imports, npm calls or package scripts.
/// Foreign targets must be rejected before this function by the inspecting caller.
pub fn discover(input: &Path, requested_target: Option<&str>) -> Result<DiscoveredNode> {
    if let Some(target) = requested_target {
        if target != host_target()? {
            return Err(error(
                DiagnosticCode::TargetMismatch,
                "cannot execute a foreign-target Node discovery probe",
            ));
        }
    }
    let executable = if input.is_dir() {
        input.join("bin/node")
    } else {
        input.to_owned()
    };
    let executable = fs::canonicalize(&executable).map_err(|e| {
        error(
            DiagnosticCode::MissingInput,
            format!("{}: {e}", executable.display()),
        )
    })?;
    let metadata = fs::metadata(&executable)
        .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "Node executable must be a regular file no larger than 512 MiB",
        ));
    }
    let bytes =
        fs::read(&executable).map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let stdout = bounded_probe(&executable)?;
    let probe: Probe = serde_json::from_slice(&stdout).map_err(|e| {
        error(
            DiagnosticCode::InvalidConfiguration,
            format!("malformed Node probe: {e}"),
        )
    })?;
    if !probe.hooks || probe.node_api < 8 {
        return Err(error(
            DiagnosticCode::UnsupportedCapability,
            "Node must expose synchronous registerHooks and Node-API 8",
        ));
    }
    let target = match (probe.platform.as_str(), probe.arch.as_str()) {
        ("darwin", "arm64") => "aarch64-apple-darwin",
        ("darwin", "x64") => "x86_64-apple-darwin",
        ("linux", "arm64") => "aarch64-unknown-linux-gnu",
        ("linux", "x64") => "x86_64-unknown-linux-gnu",
        _ => {
            return Err(error(
                DiagnosticCode::TargetMismatch,
                "unsupported Node OS/architecture",
            ));
        }
    };
    if target != host_target()? {
        return Err(error(
            DiagnosticCode::TargetMismatch,
            "Node probe target differs from host",
        ));
    }
    let version: Vec<_> = probe.version.split('.').collect();
    if version.len() != 3 {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "Node version must have three numeric components",
        ));
    }
    let parse = |i: usize| {
        version[i]
            .parse()
            .map_err(|_| error(DiagnosticCode::InvalidConfiguration, "invalid Node version"))
    };
    let abi = RuntimeAbi::Node {
        version: RuntimeVersion {
            major: parse(0)?,
            minor: parse(1)?,
            patch: parse(2)?,
        },
        node_api: probe.node_api,
        addon_abi: probe.addon_abi,
        bridge_revision: crate::BRIDGE_REVISION.into(),
    };
    Ok(DiscoveredNode {
        executable,
        descriptor: RuntimeDescriptor {
            implementation: RuntimeImplementation::Node,
            version: probe.version,
            target: target.into(),
            abi,
            provider: RuntimeProvider::Bundled,
            executable: "runtime/node".into(),
            inputs: BTreeMap::from([("node-executable".into(), InputIdentity::of(&bytes))]),
            requirements: BTreeSet::from([
                "synchronous-node-module-hooks".into(),
                "node-api>=8".into(),
            ]),
        },
    })
}
pub fn host_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        _ => Err(error(
            DiagnosticCode::TargetMismatch,
            "unsupported Node host",
        )),
    }
}
fn bounded_probe(executable: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new(executable)
        .args(["--no-addons", "-p", PROBE])
        .env_clear()
        .env("NODE_DISABLE_COMPILE_CACHE", "1")
        .env("PATH", "/glue-no-tools")
        .env("HOME", "/glue-no-home")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| error(DiagnosticCode::RuntimeProcessFailure, e.to_string()))?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let read = |mut pipe: Box<dyn Read + Send>| {
        let mut bytes = Vec::new();
        let result = pipe.by_ref().take(65537).read_to_end(&mut bytes);
        (result, bytes)
    };
    let out = thread::spawn(move || read(Box::new(out)));
    let err = thread::spawn(move || read(Box::new(err)));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(
                    DiagnosticCode::RuntimeProcessFailure,
                    "Node probe exceeded five seconds or could not be waited",
                ));
            }
        }
    };
    let (out_result, stdout) = out.join().map_err(|_| {
        error(
            DiagnosticCode::RuntimeProcessFailure,
            "Node probe reader failed",
        )
    })?;
    let (err_result, stderr) = err.join().map_err(|_| {
        error(
            DiagnosticCode::RuntimeProcessFailure,
            "Node probe reader failed",
        )
    })?;
    if out_result.is_err() || err_result.is_err() || stdout.len() > 65536 || stderr.len() > 65536 {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "Node probe output exceeds 64 KiB",
        ));
    }
    if !status.success() {
        return Err(error(
            DiagnosticCode::RuntimeProcessFailure,
            format!("Node probe failed: {}", String::from_utf8_lossy(&stderr)),
        ));
    }
    Ok(stdout)
}
/// Assemble a provider after C03/C04 have resolved its native runtime closure.
/// `closure` contains only deployment-relative payload paths; its root must be
/// `runtime/node`. No dependency discovery or original-prefix search happens at run.
pub fn prepare(
    node: DiscoveredNode,
    bridge: &Path,
    mut closure: BTreeMap<String, PathBuf>,
    native: NativeInventory,
    host: bool,
) -> Result<NodeProvider> {
    let bridge = fs::canonicalize(bridge)
        .map_err(|e| error(DiagnosticCode::MissingInput, format!("archive bridge: {e}")))?;
    if bridge.extension().and_then(|v| v.to_str()) != Some("node") {
        return Err(error(
            DiagnosticCode::InvalidConfiguration,
            "bridge must have the .node extension",
        ));
    }
    let bridge_bytes =
        fs::read(&bridge).map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
    let mut runtime = node.descriptor;
    runtime
        .inputs
        .insert("archive-bridge".into(), InputIdentity::of(&bridge_bytes));
    if host {
        runtime.provider = RuntimeProvider::Host;
        runtime.executable = node.executable.to_string_lossy().into_owned();
        runtime
            .requirements
            .insert(format!("explicit-host-node:{}", runtime.version));
    } else {
        closure.insert("runtime/node".into(), node.executable);
    }
    let mut payloads: BTreeMap<_, _> = closure
        .into_iter()
        .map(|(p, s)| (p, NodePayload::File(s)))
        .collect();
    payloads.insert("support/archive.node".into(), NodePayload::File(bridge));
    payloads.insert(
        "support/node-bootstrap.cjs".into(),
        NodePayload::Bytes {
            bytes: crate::BOOTSTRAP.as_bytes().to_vec(),
            mode: 0o444,
        },
    );
    payloads.insert(
        "support/resolver.cjs".into(),
        NodePayload::Bytes {
            bytes: crate::RESOLVER.as_bytes().to_vec(),
            mode: 0o444,
        },
    );
    let launch = RuntimeLaunchSpec {
        executable: runtime.executable.clone(),
        args: vec![
            "{root}/support/node-bootstrap.cjs".into(),
            "{archive}".into(),
            "{root}/support/archive.node".into(),
        ],
        environment: BTreeMap::from([
            ("NODE_DISABLE_COMPILE_CACHE".into(), "1".into()),
            ("NODE_PATH".into(), "".into()),
            ("PATH".into(), "/glue-no-tools".into()),
            ("HOME".into(), "/glue-no-home".into()),
            ("TMPDIR".into(), "/glue-no-temp".into()),
        ]),
        clear_environment: true,
    };
    Ok(NodeProvider {
        runtime,
        launch,
        payloads,
        native,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn available_node() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("GLUE_NODE_TEST_EXECUTABLE") {
            return Some(p.into());
        }
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|p| p.join("node"))
            .find(|p| p.is_file())
    }
    #[test]
    fn discovers_stock_runtime_without_identity_allowlist() {
        let Some(path) = available_node() else {
            eprintln!("Node executable unavailable; runtime discovery execution not performed");
            return;
        };
        let node = discover(&path, None).unwrap();
        assert_eq!(node.descriptor.implementation, RuntimeImplementation::Node);
        assert!(matches!(
            node.descriptor.abi,
            RuntimeAbi::Node { node_api: 8.., .. }
        ));
        assert_eq!(
            node.descriptor.inputs["node-executable"],
            InputIdentity::of(&fs::read(node.executable).unwrap())
        );
    }
    #[test]
    fn missing_and_foreign_inputs_reject() {
        assert_eq!(
            discover(Path::new("/glue-missing-node"), None)
                .unwrap_err()
                .code,
            DiagnosticCode::MissingInput
        );
        assert_eq!(
            discover(Path::new("/glue-missing-node"), Some("foreign-triple"))
                .unwrap_err()
                .code,
            DiagnosticCode::TargetMismatch
        );
    }
    #[test]
    fn launch_is_literal_and_cache_disabled() {
        let Some(path) = available_node() else {
            return;
        };
        let node = discover(&path, None).unwrap();
        let dir = std::env::temp_dir().join(format!("glue-node-provider-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let bridge = dir.join("archive.node");
        fs::write(&bridge, b"not-loaded-by-preparation").unwrap();
        let provider = prepare(
            node,
            &bridge,
            BTreeMap::new(),
            NativeInventory::default(),
            true,
        )
        .unwrap();
        assert_eq!(provider.runtime.provider, RuntimeProvider::Host);
        assert!(provider.launch.clear_environment);
        assert_eq!(
            provider.launch.environment["NODE_DISABLE_COMPILE_CACHE"],
            "1"
        );
        assert!(provider.launch.args.iter().any(|a| a == "{archive}"));
        fs::remove_dir_all(dir).unwrap();
    }
}
