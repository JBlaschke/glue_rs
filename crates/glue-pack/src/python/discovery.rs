//! General installed CPython discovery. Selected runtimes are trusted build
//! programs, but application code, site hooks and package-manager tools never run.
use glue_format::{
    GilMode, InputIdentity, RuntimeAbi, RuntimeDescriptor, RuntimeImplementation, RuntimeProvider,
    RuntimeVersion,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const MAX_METADATA: u64 = 1024 * 1024;
const MAX_PROBE: u64 = 64 * 1024;
const PROBE: &str = include_str!("probe.py");

#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    pub environment: PathBuf,
    pub runtime: Option<PathBuf>,
    pub python_version: Option<String>,
    pub target: Option<String>,
    pub inspect_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMetadata {
    pub executable: PathBuf,
    pub prefix: PathBuf,
    pub stdlib: PathBuf,
    pub version: [u16; 3],
    pub version_text: String,
    pub implementation: String,
    pub machine: String,
    pub system: String,
    pub soabi: String,
    pub gil_disabled: bool,
    pub debug: bool,
    pub framework: String,
    pub extension_suffixes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedEnvironment {
    pub environment: PathBuf,
    pub runtime: RuntimeMetadata,
    pub descriptor: RuntimeDescriptor,
    pub site_packages: Vec<PathBuf>,
    pub pyvenv: BTreeMap<String, String>,
    pub console_scripts: BTreeMap<String, String>,
}

fn fail(message: impl Into<String>) -> String {
    message.into()
}

pub fn current_target() -> Result<String, String> {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => return Err(format!("unsupported target architecture {other}")),
    };
    match std::env::consts::OS {
        "macos" => Ok(format!("{arch}-apple-darwin")),
        "linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        other => Err(format!("unsupported target OS {other}")),
    }
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| format!("read {path:?}: {e}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!("input exceeds {limit} bytes: {path:?}"));
    }
    Ok(bytes)
}

/// The probe is deliberately -I -S -B. Reader allocations and waits are bounded.
/// A selected executable remains a trusted build input, not sandboxed code.
pub fn probe(executable: &Path, timeout: Duration) -> Result<RuntimeMetadata, String> {
    let mut child = Command::new(executable)
        .args(["-I", "-S", "-B", "-c", PROBE])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .spawn()
        .map_err(|e| format!("cannot probe {executable:?}: {e}"))?;
    let (send, receive) = mpsc::channel();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("missing probe stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| fail("missing probe stderr"))?;
    for (name, mut stream) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let send = send.clone();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream
                .by_ref()
                .take(MAX_PROBE + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
                .map_err(|e| e.to_string());
            let _ = send.send((name, result));
        });
    }
    drop(send);
    let deadline = Instant::now() + timeout;
    let mut outputs = BTreeMap::new();
    let status = loop {
        for (name, bytes) in receive.try_iter() {
            let bytes = bytes?;
            if bytes.len() as u64 > MAX_PROBE {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Python metadata probe exceeded output bound".into());
            }
            outputs.insert(name, bytes);
        }
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Python metadata probe exceeded timeout".into());
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    };
    while outputs.len() < 2 {
        let (name, bytes) = receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| fail("Python metadata pipe exceeded timeout"))?;
        let bytes = bytes?;
        if bytes.len() as u64 > MAX_PROBE {
            return Err("Python metadata probe exceeded output bound".into());
        }
        outputs.insert(name, bytes);
    }
    if !status.success() {
        return Err(format!(
            "Python metadata probe failed: {}",
            String::from_utf8_lossy(&outputs["stderr"])
        ));
    }
    let mut metadata: RuntimeMetadata = serde_json::from_slice(&outputs["stdout"])
        .map_err(|e| format!("malformed Python metadata: {e}"))?;
    metadata.executable = fs::canonicalize(executable).map_err(|e| e.to_string())?;
    validate_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_metadata(metadata: &RuntimeMetadata) -> Result<(), String> {
    if metadata.implementation != "cpython" || metadata.version[0] != 3 || metadata.version[1] < 11
    {
        return Err("requires CPython 3.11 or newer".into());
    }
    if metadata.gil_disabled {
        return Err("unsupported capability: free-threaded CPython ABI".into());
    }
    if metadata.debug {
        return Err("unsupported capability: debug CPython ABI".into());
    }
    if metadata.soabi.is_empty()
        || metadata.extension_suffixes.is_empty()
        || metadata.extension_suffixes.len() > 32
        || metadata
            .extension_suffixes
            .iter()
            .any(|s| s.len() > 128 || s.contains('/') || !s.starts_with('.'))
    {
        return Err("malformed Python ABI/extension suffix metadata".into());
    }
    if !metadata.prefix.is_absolute()
        || !metadata.stdlib.is_absolute()
        || !metadata.stdlib.starts_with(&metadata.prefix)
    {
        return Err("Python stdlib must belong to its declared absolute runtime prefix".into());
    }
    Ok(())
}

/// Do not let Rosetta/binfmt implicitly turn foreign inspection into execution.
pub fn validate_native_executable(path: &Path) -> Result<(), String> {
    let mut header = [0u8; 4096];
    let count = File::open(path)
        .map_err(|e| e.to_string())?
        .read(&mut header)
        .map_err(|e| e.to_string())?;
    let bytes = &header[..count];
    let host_arm = std::env::consts::ARCH == "aarch64";
    let matches = if bytes.starts_with(b"\x7fELF") && bytes.len() >= 20 {
        if std::env::consts::OS != "linux" {
            false
        } else {
            let arch = if bytes[5] == 1 {
                u16::from_le_bytes([bytes[18], bytes[19]])
            } else {
                u16::from_be_bytes([bytes[18], bytes[19]])
            };
            bytes[4] == 2 && arch == if host_arm { 183 } else { 62 }
        }
    } else if bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) && bytes.len() >= 8 {
        let arch = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| fail("short Mach-O header"))?,
        );
        std::env::consts::OS == "macos" && arch == if host_arm { 0x0100000c } else { 0x01000007 }
    } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && bytes.len() >= 8 {
        let slices = u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| fail("short fat header"))?,
        ) as usize;
        if slices > 64 || bytes.len() < 8 + slices * 20 {
            return Err("malformed/unbounded Mach-O slice table".into());
        }
        std::env::consts::OS == "macos"
            && (0..slices).any(|index| {
                u32::from_be_bytes(
                    bytes[8 + index * 20..12 + index * 20]
                        .try_into()
                        .unwrap_or_default(),
                ) == if host_arm { 0x0100000c } else { 0x01000007 }
            })
    } else {
        return Err("selected Python must be a native ELF/Mach-O executable; inspect foreign metadata separately".into());
    };
    if matches {
        Ok(())
    } else {
        Err("foreign Python executable target; inspection never executes it".into())
    }
}

pub fn executable_in(input: &Path) -> Result<PathBuf, String> {
    if input.is_file() {
        return fs::canonicalize(input).map_err(|e| e.to_string());
    }
    for path in [input.join("bin/python3"), input.join("bin/python")] {
        if path.is_file() {
            return fs::canonicalize(path).map_err(|e| e.to_string());
        }
    }
    let bin = input.join("bin");
    let mut candidates = fs::read_dir(&bin)
        .map_err(|e| format!("missing supplied Python executable in {bin:?}: {e}"))?
        .take(256)
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                s.starts_with("python3.") && s[8..].chars().all(|c| c.is_ascii_digit())
            }) && p.is_file()
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    if candidates.len() == 1 {
        fs::canonicalize(&candidates[0]).map_err(|e| e.to_string())
    } else {
        Err(format!("missing or ambiguous Python executable in {bin:?}"))
    }
}

fn parse_config(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let bytes = read_bounded(path, 64 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed pyvenv.cfg line: {line}"))?;
        if result
            .insert(key.trim().to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate pyvenv.cfg key".into());
        }
    }
    Ok(result)
}

pub fn discover(options: &DiscoveryOptions) -> Result<ResolvedEnvironment, String> {
    let environment = fs::canonicalize(&options.environment)
        .map_err(|e| format!("missing Python environment {:?}: {e}", options.environment))?;
    let target = options.target.clone().unwrap_or(current_target()?);
    if options.inspect_only || target != current_target()? {
        return Err("inspection-only/foreign runtime: use inspect_pbs_tar or inspect_tree; exact executable ABI facts are unavailable without a declared native probe".into());
    }
    let cfg_path = environment.join("pyvenv.cfg");
    let pyvenv = if cfg_path.exists() {
        parse_config(&cfg_path)?
    } else {
        BTreeMap::new()
    };
    if pyvenv
        .get("include-system-site-packages")
        .is_some_and(|s| s.eq_ignore_ascii_case("true"))
    {
        return Err("system-site-packages is unsupported; supply an isolated environment".into());
    }
    let env_executable = executable_in(&environment)
        .map_err(|e| format!("environment base runtime is missing: {e}"))?;
    validate_native_executable(&env_executable)?;
    let env_metadata = probe(&env_executable, Duration::from_secs(15))?;
    let runtime = if let Some(path) = &options.runtime {
        let executable = executable_in(path)?;
        validate_native_executable(&executable)?;
        probe(&executable, Duration::from_secs(15))?
    } else {
        env_metadata.clone()
    };
    if runtime.version[..2] != env_metadata.version[..2]
        || runtime.soabi != env_metadata.soabi
        || runtime.gil_disabled != env_metadata.gil_disabled
        || runtime.debug != env_metadata.debug
    {
        return Err(format!(
            "Python runtime ABI mismatch: environment {} vs override {}",
            env_metadata.soabi, runtime.soabi
        ));
    }
    if let Some(requested) = &options.python_version {
        let numeric = requested.strip_prefix("==").unwrap_or(requested).split('.').map(str::parse::<u16>).collect::<Result<Vec<_>, _>>().map_err(|_| fail("Python version constraint must be MAJOR.MINOR[.PATCH] or ==MAJOR.MINOR[.PATCH]"))?;
        if !(2..=3).contains(&numeric.len()) || !runtime.version.starts_with(&numeric) {
            return Err(format!("selected Python does not satisfy {requested}"));
        }
    }
    let runtime_target = metadata_target(&runtime)?;
    if runtime_target != target {
        return Err(format!(
            "Python runtime target mismatch: {runtime_target} vs {target}"
        ));
    }
    let version = format!("{}.{}", runtime.version[0], runtime.version[1]);
    let mut site_packages = vec![environment.join(format!("lib/python{version}/site-packages"))];
    if !cfg_path.exists() {
        site_packages.push(
            runtime
                .prefix
                .join(format!("lib/python{version}/site-packages")),
        );
    }
    site_packages.retain(|p| p.is_dir());
    site_packages.sort();
    site_packages.dedup();
    let mut console_scripts = BTreeMap::new();
    for site in &site_packages {
        let mut count = 0usize;
        for entry in fs::read_dir(site).map_err(|e| e.to_string())? {
            count += 1;
            if count > 50_000 {
                return Err("site-packages entry count exceeds bound".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_name().to_string_lossy().ends_with(".dist-info") {
                continue;
            }
            let path = entry.path().join("entry_points.txt");
            if !path.is_file() {
                continue;
            }
            for (name, value) in console_entries(&read_bounded(&path, MAX_METADATA)?)? {
                if console_scripts.insert(name.clone(), value).is_some() {
                    return Err(format!("ambiguous console script {name}"));
                }
            }
        }
    }
    let executable_bytes = read_bounded(&runtime.executable, 256 * 1024 * 1024)?;
    let mut inputs = BTreeMap::new();
    inputs.insert(
        "runtime-executable".into(),
        InputIdentity::of(&executable_bytes),
    );
    if cfg_path.exists() {
        inputs.insert(
            "pyvenv.cfg".into(),
            InputIdentity::of(&read_bounded(&cfg_path, 64 * 1024)?),
        );
    }
    let descriptor = RuntimeDescriptor {
        implementation: RuntimeImplementation::Cpython,
        version: runtime
            .version
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("."),
        target,
        abi: RuntimeAbi::Python {
            version: RuntimeVersion {
                major: runtime.version[0],
                minor: runtime.version[1],
                patch: runtime.version[2],
            },
            gil: GilMode::Conventional,
            debug: false,
        },
        provider: RuntimeProvider::Bundled,
        executable: format!("runtime/bin/python{version}"),
        inputs,
        requirements: BTreeSet::from([format!("SOABI={}", runtime.soabi)]),
    };
    Ok(ResolvedEnvironment {
        environment,
        runtime,
        descriptor,
        site_packages,
        pyvenv,
        console_scripts,
    })
}

pub fn metadata_target(metadata: &RuntimeMetadata) -> Result<String, String> {
    let arch = match metadata.machine.as_str() {
        "arm64" | "aarch64" => "aarch64",
        "x86_64" | "AMD64" => "x86_64",
        other => return Err(format!("unsupported Python architecture {other}")),
    };
    match metadata.system.as_str() {
        "Darwin" => Ok(format!("{arch}-apple-darwin")),
        "Linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        other => Err(format!("unsupported Python OS {other}")),
    }
}

pub fn console_entries(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let mut active = false;
    let mut result = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            active = line == "[console_scripts]";
            continue;
        }
        if !active || line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (name, entry) = line
            .split_once('=')
            .ok_or_else(|| fail("malformed console entry"))?;
        let (name, entry) = (name.trim(), entry.trim());
        if name.is_empty() || !entry.contains(':') || entry.contains(['\n', '\r']) {
            return Err("malformed console entry target".into());
        }
        if result.insert(name.to_owned(), entry.to_owned()).is_some() {
            return Err(format!("duplicate console entry {name}"));
        }
    }
    Ok(result)
}

/// Parse the existing safe PBS tar reader with no hash catalog or execution.
/// Compression is selected from bytes, not a filename or version allowlist.
pub fn inspect_pbs_archive(path: &Path) -> Result<glue_pbs::archive::Inventory, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 1024 * 1024 * 1024 {
        return Err("compressed runtime archive exceeds 1 GiB bound".into());
    }
    let mut source = BufReader::new(file.take(1024 * 1024 * 1024));
    use std::io::BufRead;
    let prefix = source.fill_buf().map_err(|e| e.to_string())?;
    let limits = glue_pbs::archive::Limits::default();
    if prefix.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::bufread::GzDecoder::new(source);
        let inventory = glue_pbs::archive::read_inventory(&mut decoder, &limits)?;
        let mut source = decoder.into_inner();
        if !source.fill_buf().map_err(|e| e.to_string())?.is_empty() {
            return Err("runtime archive contains trailing bytes or another gzip member".into());
        }
        Ok(inventory)
    } else if prefix.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let mut decoder =
            ruzstd::decoding::StreamingDecoder::new_with_max_window_size(source, 128 * 1024 * 1024)
                .map_err(|e| e.to_string())?;
        let inventory = glue_pbs::archive::read_inventory(&mut decoder, &limits)?;
        if !decoder.decoder.is_finished()
            || decoder
                .decoder
                .get_checksum_from_data()
                .is_some_and(|expected| Some(expected) != decoder.decoder.get_calculated_checksum())
        {
            return Err("runtime archive zstd checksum/frame did not complete".into());
        }
        let mut source = decoder.into_inner();
        if !source.fill_buf().map_err(|e| e.to_string())?.is_empty() {
            return Err("runtime archive contains trailing bytes or another zstd frame".into());
        }
        Ok(inventory)
    } else {
        glue_pbs::archive::read_inventory(source, &limits)
    }
}

#[derive(Debug, Serialize)]
pub struct TreeInspection {
    pub root: PathBuf,
    pub stdlib_candidates: Vec<PathBuf>,
    pub pbs_metadata: Option<serde_json::Value>,
    pub executed: bool,
}

pub fn inspect_tree(root: &Path) -> Result<TreeInspection, String> {
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut stdlib_candidates = Vec::new();
    for entry in fs::read_dir(root.join("lib"))
        .map_err(|e| e.to_string())?
        .take(1024)
    {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name().to_string_lossy().starts_with("python3.") && entry.path().is_dir() {
            stdlib_candidates.push(entry.path());
        }
    }
    stdlib_candidates.sort();
    let metadata = root.join("PYTHON.json");
    let pbs_metadata = if metadata.is_file() {
        Some(
            serde_json::from_slice(&read_bounded(&metadata, MAX_METADATA)?)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    Ok(TreeInspection {
        root,
        stdlib_candidates,
        pbs_metadata,
        executed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_metadata_is_not_executed() {
        let scripts = console_entries(
            b"[console_scripts]\nhello = package.cli:main\n[other]\nx = ignored:main\n",
        )
        .unwrap();
        assert_eq!(scripts["hello"], "package.cli:main");
        assert_eq!(scripts.len(), 1);
    }
    #[test]
    fn malformed_console_entries_reject() {
        assert!(console_entries(b"[console_scripts]\nx = no_callable\n").is_err());
    }
    #[test]
    fn foreign_target_stops_before_probe() {
        let options = DiscoveryOptions {
            environment: std::env::current_dir().unwrap(),
            runtime: Some(PathBuf::from("/never/execute")),
            python_version: None,
            target: Some("foreign".into()),
            inspect_only: false,
        };
        assert!(discover(&options).unwrap_err().contains("foreign"));
    }
    #[test]
    fn no_upper_python_version_ceiling() {
        let metadata:RuntimeMetadata=serde_json::from_str(r#"{"executable":"/x","prefix":"/x","stdlib":"/x/lib/python3.99","version":[3,99,1],"version_text":"future","implementation":"cpython","machine":"arm64","system":"Darwin","soabi":"cpython-399-darwin","gil_disabled":false,"debug":false,"framework":"","extension_suffixes":[".so"]}"#).unwrap();
        assert!(validate_metadata(&metadata).is_ok());
    }
}
