//! Mach-O closure collection using dyld metadata and explicit build-time normalization.
use super::{
    NativeCollection, NativeFacts, NativeRequest, NativeSearchRoot, diagnostic, read_image,
    relative_path,
};
use crate::distribution::{PayloadSource, Result};
use glue_format::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
fn bad(message: impl Into<String>) -> Diagnostic {
    diagnostic(DiagnosticCode::UnsupportedCapability, message)
}
struct Image<'a>(&'a [u8]);
impl Image<'_> {
    fn range(&self, p: usize, n: usize) -> Result<&[u8]> {
        self.0
            .get(
                p..p.checked_add(n)
                    .ok_or_else(|| bad("Mach-O offset overflow"))?,
            )
            .ok_or_else(|| bad("Mach-O command outside image"))
    }
    fn u32(&self, p: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.range(p, 4)?.try_into().unwrap()))
    }
    fn text(&self, start: usize, end: usize) -> Result<String> {
        let b = self.range(
            start,
            end.checked_sub(start)
                .ok_or_else(|| bad("Mach-O string range"))?,
        )?;
        let n = b
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| bad("unterminated Mach-O load path"))?;
        if n > 65536 {
            return Err(bad("Mach-O load path exceeds bound"));
        }
        std::str::from_utf8(&b[..n])
            .map(str::to_owned)
            .map_err(|_| bad("non-UTF8 Mach-O load path"))
    }
}
fn architecture(cpu: u32) -> Result<&'static str> {
    match cpu {
        0x01000007 => Ok("x86_64"),
        0x0100000c => Ok("aarch64"),
        _ => Err(bad("unsupported Mach-O CPU slice")),
    }
}
fn version(n: u32) -> String {
    format!("{}.{}.{}", n >> 16, (n >> 8) & 255, n & 255)
}
/// Select an actual slice, retaining all original bytes when staging a universal image.
pub fn inspect_bytes(bytes: &[u8], requested_arch: Option<&str>) -> Result<NativeFacts> {
    if bytes.len() < 4 {
        return Err(bad("truncated Mach-O header"));
    }
    if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        let wide = bytes[3] == 0xbf;
        let e = Image(bytes);
        let count = u32::from_be_bytes(e.range(4, 4)?.try_into().unwrap()) as usize;
        if count == 0 || count > 64 {
            return Err(bad("invalid universal Mach-O slice count"));
        }
        let wanted = requested_arch.unwrap_or(if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        });
        let mut selected = None;
        let mut ranges = Vec::new();
        for i in 0..count {
            let p = 8 + i * if wide { 32 } else { 20 };
            let cpu = u32::from_be_bytes(e.range(p, 4)?.try_into().unwrap());
            let (o, n) = if wide {
                (
                    u64::from_be_bytes(e.range(p + 8, 8)?.try_into().unwrap()),
                    u64::from_be_bytes(e.range(p + 16, 8)?.try_into().unwrap()),
                )
            } else {
                (
                    u64::from(u32::from_be_bytes(e.range(p + 8, 4)?.try_into().unwrap())),
                    u64::from(u32::from_be_bytes(e.range(p + 12, 4)?.try_into().unwrap())),
                )
            };
            let end = o
                .checked_add(n)
                .ok_or_else(|| bad("universal Mach-O slice overflow"))?;
            if o < 8 + (count * if wide { 32 } else { 20 }) as u64
                || end > bytes.len() as u64
                || ranges.iter().any(|(a, b)| o < *b && *a < end)
            {
                return Err(bad("overlapping/outside universal Mach-O slice"));
            }
            ranges.push((o, end));
            if architecture(cpu).is_ok_and(|a| a == wanted)
                && selected.replace((o as usize, n as usize)).is_some()
            {
                return Err(bad("ambiguous Mach-O CPU slices"));
            }
        }
        let (o, n) = selected.ok_or_else(|| {
            diagnostic(
                DiagnosticCode::TargetMismatch,
                format!("Mach-O lacks {wanted} slice"),
            )
        })?;
        return inspect_bytes(e.range(o, n)?, Some(wanted));
    }
    let e = Image(bytes);
    if e.u32(0)? != 0xfeedfacf {
        return Err(bad("expected little-endian 64-bit Mach-O"));
    }
    let arch = architecture(e.u32(4)?)?;
    if requested_arch.is_some_and(|a| a != arch) {
        return Err(diagnostic(
            DiagnosticCode::TargetMismatch,
            format!("Mach-O {arch} does not match requested slice"),
        ));
    }
    let kind = match e.u32(12)? {
        2 => "executable",
        6 => "dylib",
        8 => "bundle",
        _ => return Err(bad("Mach-O must be executable, dylib or bundle")),
    };
    let count = e.u32(16)? as usize;
    let size = e.u32(20)? as usize;
    if count > 65536 || size > 32 * 1024 * 1024 {
        return Err(bad("Mach-O load command table exceeds bound"));
    }
    e.range(32, size)?;
    let mut dependencies = Vec::new();
    let mut identity = None;
    let mut search_paths = Vec::new();
    let mut minimum_os = None;
    let mut features = BTreeSet::new();
    let mut p = 32;
    for _ in 0..count {
        let command = e.u32(p)? & 0x7fffffff;
        let n = e.u32(p + 4)? as usize;
        if n < 8 || n % 8 != 0 || p + n > 32 + size {
            return Err(bad("invalid Mach-O load command size"));
        }
        match command {
            0xc | 0x18 | 0x1f | 0x23 | 0xd => {
                if n < 24 {
                    return Err(bad("short Mach-O dylib command"));
                }
                let o = e.u32(p + 8)? as usize;
                if o < 24 || o >= n {
                    return Err(bad("Mach-O dylib string offset"));
                }
                let name = e.text(p + o, p + n)?;
                if command == 0xd {
                    if identity.replace(name).is_some() {
                        return Err(bad("duplicate Mach-O dylib identity"));
                    }
                } else {
                    dependencies.push(name);
                }
            }
            0x1c => {
                let o = e.u32(p + 8)? as usize;
                if o < 12 || o >= n {
                    return Err(bad("Mach-O rpath string offset"));
                }
                search_paths.push(e.text(p + o, p + n)?);
            }
            0x32 => {
                if n < 24 || e.u32(p + 8)? != 1 {
                    return Err(bad("Mach-O build platform must be macOS"));
                }
                minimum_os = Some(version(e.u32(p + 12)?));
            }
            0x24 => {
                if n < 16 {
                    return Err(bad("short Mach-O OS floor"));
                }
                minimum_os = Some(version(e.u32(p + 8)?));
            }
            0x1d => {
                features.insert("code_signature".into());
            }
            0x34 => {
                features.insert("chained_fixups".into());
            }
            0x22 => {
                features.insert("dyld_info".into());
            }
            0x19 => {
                if n < 72 {
                    return Err(bad("short Mach-O segment"));
                }
                let sections = e.u32(p + 64)? as usize;
                if sections > 65536 || 72 + sections * 80 > n {
                    return Err(bad("Mach-O sections outside command"));
                }
                for i in 0..sections {
                    let flags = e.u32(p + 72 + i * 80 + 64)? & 255;
                    if (0x11..=0x15).contains(&flags) {
                        features.insert("tls".into());
                    }
                }
            }
            _ => (),
        }
        p += n;
    }
    if p != 32 + size {
        return Err(bad("Mach-O load commands do not fill declared table"));
    }
    Ok(NativeFacts {
        format: "macho".into(),
        architecture: arch.into(),
        kind: kind.into(),
        dependencies,
        identity,
        search_paths,
        minimum_os,
        versions: BTreeSet::new(),
        features,
        interpreter: None,
    })
}
fn system(name: &str) -> bool {
    name.starts_with("/usr/lib/") || name.starts_with("/System/Library/")
}
fn expand(value: &str, loader: &Path, executable: Option<&Path>) -> Result<PathBuf> {
    if let Some(s) = value.strip_prefix("@loader_path") {
        return Ok(loader.join(s.trim_start_matches('/')));
    }
    if let Some(s) = value.strip_prefix("@executable_path") {
        return executable
            .map(|p| p.join(s.trim_start_matches('/')))
            .ok_or_else(|| {
                bad("@executable_path requires the actual selected executable in native roots")
            });
    }
    if value.starts_with('/') {
        return Ok(PathBuf::from(value));
    }
    Err(bad(format!("unsupported/cwd-relative dyld path {value}")))
}
fn locate(
    path: &Path,
    roots: &[NativeSearchRoot],
) -> Result<(PathBuf, String, DependencyProvider)> {
    let p = fs::canonicalize(path).map_err(|e| {
        diagnostic(
            DiagnosticCode::MissingDependency,
            format!("{}: {e}", path.display()),
        )
    })?;
    let r = roots
        .iter()
        .find(|r| p.starts_with(&r.source))
        .ok_or_else(|| {
            diagnostic(
                DiagnosticCode::PathEscape,
                format!("{} escapes declared native roots", path.display()),
            )
        })?;
    let logical = format!(
        "{}/{}",
        r.deployed,
        p.strip_prefix(&r.source).unwrap().to_string_lossy()
    );
    validate_payload_path(&logical)
        .map_err(|e| diagnostic(DiagnosticCode::PathEscape, e.to_string()))?;
    Ok((p, logical, r.provider.clone()))
}
fn numeric(value: &str) -> Vec<u32> {
    value
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .chain(std::iter::repeat(0))
        .take(3)
        .collect()
}
/// Resolve @rpath using each actual loader's chain, never a flattened basename pool.
pub fn collect(request: &NativeRequest) -> Result<NativeCollection> {
    let arch = if request.target.starts_with("aarch64-") {
        "aarch64"
    } else if request.target.starts_with("x86_64-") {
        "x86_64"
    } else {
        return Err(diagnostic(
            DiagnosticCode::TargetMismatch,
            "unsupported macOS architecture",
        ));
    };
    let mut roots = Vec::new();
    for r in &request.search_roots {
        validate_payload_path(&r.deployed)
            .map_err(|e| diagnostic(DiagnosticCode::PathEscape, e.to_string()))?;
        roots.push(NativeSearchRoot {
            source: fs::canonicalize(&r.source)
                .map_err(|e| diagnostic(DiagnosticCode::MissingInput, e.to_string()))?,
            deployed: r.deployed.clone(),
            provider: r.provider.clone(),
        });
    }
    roots.sort_by_key(|r| std::cmp::Reverse(r.source.components().count()));
    let mut executable = None;
    for image in &request.images {
        let facts = inspect_bytes(&read_image(image)?, Some(arch))?;
        if facts.kind == "executable"
            && executable
                .replace(fs::canonicalize(image).map_err(|e| bad(e.to_string()))?)
                .is_some()
        {
            return Err(bad("native request has multiple executable contexts"));
        }
    }
    let executable_dir = executable.as_ref().and_then(|p| p.parent());
    let host_floor = if cfg!(target_os = "macos") {
        Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
    } else {
        None
    };
    let mut queue = VecDeque::new();
    let mut result = NativeCollection::default();
    let mut contexts: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for image in &request.images {
        let (p, d, _) = locate(image, &roots)?;
        result.inventory.roots.insert(d.clone(), d);
        queue.push_back((p, Vec::<PathBuf>::new()));
    }
    let mut identities = BTreeMap::<String, (String, String)>::new();
    while let Some((source, inherited)) = queue.pop_front() {
        if result.mappings.contains_key(&source) {
            continue;
        }
        if result.mappings.len() >= 100000 {
            return Err(bad("native closure exceeds image bound"));
        }
        let (_, deployed, _) = locate(&source, &roots)?;
        let bytes = read_image(&source)?;
        let facts = inspect_bytes(&bytes, Some(arch))?;
        if let (Some(floor), Some(host)) = (&facts.minimum_os, &host_floor) {
            if numeric(floor) > numeric(host) {
                return Err(diagnostic(
                    DiagnosticCode::TargetMismatch,
                    format!("{deployed} needs macOS {floor}, builder host is {host}"),
                ));
            }
        }
        if let Some(floor) = &facts.minimum_os {
            result
                .inventory
                .host_requirements
                .insert(format!("macos>={floor}"));
        }
        if let Some(id) = &facts.identity {
            let hash = digest(&bytes);
            if let Some((previous, path)) = identities.get(id) {
                if previous != &hash {
                    return Err(diagnostic(
                        DiagnosticCode::MissingDependency,
                        format!("conflicting dylib identity {id}: {path} / {deployed}"),
                    ));
                }
            }
            identities.insert(id.clone(), (hash, deployed.clone()));
        }
        let parent = source.parent().unwrap();
        let mut paths = Vec::new();
        for p in &facts.search_paths {
            paths.push(expand(p, parent, executable_dir)?);
        }
        paths.extend(inherited);
        contexts.insert(source.clone(), paths.clone());
        let absolute_rpath = facts
            .search_paths
            .iter()
            .any(|p| p.starts_with('/') && !system(p));
        if !request.normalize
            && (absolute_rpath
                || facts
                    .identity
                    .as_ref()
                    .is_some_and(|id| id.starts_with('/') && !system(id)))
        {
            return Err(diagnostic(
                DiagnosticCode::TransformationRequired,
                format!(
                    "{deployed}: absolute dylib ID/rpath leaks a host prefix; --normalize-native-paths will replace ID/dependency paths and re-sign ad-hoc"
                ),
            ));
        }
        result.mappings.insert(source.clone(), deployed.clone());
        result
            .payloads
            .insert(deployed.clone(), PayloadSource::File(source.clone()));
        result
            .inventory
            .features
            .extend(facts.features.iter().cloned());
        for needed in &facts.dependencies {
            if system(needed) || request.host_libraries.contains(needed) {
                let provider = if system(needed) {
                    DependencyProvider::OperatingSystem
                } else {
                    DependencyProvider::Host
                };
                result.inventory.host_requirements.insert(needed.clone());
                result.inventory.edges.push(NativeDependency {
                    from: deployed.clone(),
                    name: needed.clone(),
                    provider,
                    resolved: needed.clone(),
                });
                continue;
            }
            let candidates = if let Some(s) = needed.strip_prefix("@rpath/") {
                paths.iter().map(|p| p.join(s)).collect::<Vec<_>>()
            } else if needed.starts_with('@') || needed.starts_with('/') {
                vec![expand(needed, parent, executable_dir)?]
            } else {
                roots.iter().map(|r| r.source.join(needed)).collect()
            };
            let mut found = Vec::new();
            for p in candidates {
                if p.is_file() {
                    let item = locate(&p, &roots)?;
                    if !found.iter().any(|(x, _, _)| x == &item.0) {
                        found.push(item);
                    }
                }
            }
            if found.is_empty() {
                return Err(diagnostic(
                    DiagnosticCode::MissingDependency,
                    format!("{deployed} -> {needed}: missing in loader's actual rpath chain"),
                ));
            }
            // Multiple real candidates in an @rpath chain bind to dyld's first match;
            // ambiguous explicit basename lookup has no such reliable context.
            if !needed.starts_with('@') && !needed.starts_with('/') && found.len() > 1 {
                return Err(diagnostic(
                    DiagnosticCode::MissingDependency,
                    format!("{deployed} -> {needed}: ambiguous supplied images"),
                ));
            }
            let (resolved, path, provider) = found.remove(0);
            if !request.normalize
                && (!needed.starts_with('@')
                    || needed.starts_with("@executable_path") && executable_dir.is_none())
            {
                return Err(diagnostic(
                    DiagnosticCode::TransformationRequired,
                    format!(
                        "{deployed} -> {needed}: propose -change to @loader_path/{} and re-sign; use --normalize-native-paths",
                        relative_path(Path::new(&deployed).parent().unwrap(), Path::new(&path))
                    ),
                ));
            }
            result.inventory.edges.push(NativeDependency {
                from: deployed.clone(),
                name: needed.clone(),
                provider,
                resolved: path,
            });
            queue.push_back((resolved, paths.clone()));
        }
        result.facts.insert(deployed, facts);
    }
    if request.normalize {
        for (source, deployed) in &result.mappings {
            let facts = &result.facts[deployed];
            let mut edits = Vec::<(String, String)>::new();
            for edge in result.inventory.edges.iter().filter(|e| {
                &e.from == deployed
                    && matches!(
                        e.provider,
                        DependencyProvider::Bundled | DependencyProvider::Runtime
                    )
            }) {
                let new = format!(
                    "@loader_path/{}",
                    relative_path(
                        Path::new(deployed).parent().unwrap(),
                        Path::new(&edge.resolved)
                    )
                );
                if edge.name != new {
                    edits.push((edge.name.clone(), new));
                }
            }
            let id = facts
                .identity
                .as_ref()
                .filter(|id| id.starts_with('/') && !system(id))
                .map(|_| {
                    format!(
                        "@rpath/{}",
                        Path::new(deployed).file_name().unwrap().to_string_lossy()
                    )
                });
            let remove: Vec<_> = facts
                .search_paths
                .iter()
                .filter(|p| p.starts_with('/') && !system(p))
                .cloned()
                .collect();
            if !edits.is_empty() || id.is_some() || !remove.is_empty() {
                let (bytes, change) =
                    normalize_image(source, deployed, &edits, id.as_deref(), &remove)?;
                result.payloads.insert(
                    deployed.clone(),
                    PayloadSource::Bytes {
                        bytes,
                        mode: if facts.kind == "executable" {
                            0o755
                        } else {
                            0o644
                        },
                    },
                );
                result.inventory.transformations.push(change);
            }
        }
    }
    result
        .inventory
        .edges
        .sort_by(|a, b| (&a.from, &a.name).cmp(&(&b.from, &b.name)));
    Ok(result)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(tool: &str, args: &[String], path: &Path) -> Result<()> {
    let status = Command::new(tool)
        .args(args)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| bad(format!("{tool}: {e}")))?;
    if !status.success() {
        return Err(diagnostic(
            DiagnosticCode::TransformationRequired,
            format!("{tool} failed while editing/verifying {}", path.display()),
        ));
    }
    Ok(())
}
fn normalize_image(
    source: &Path,
    deployed: &str,
    edits: &[(String, String)],
    id: Option<&str>,
    remove: &[String],
) -> Result<(Vec<u8>, Transformation)> {
    if !cfg!(target_os = "macos") {
        return Err(bad(
            "Mach-O normalization requires native macOS install_name_tool/codesign",
        ));
    }
    static N: AtomicU64 = AtomicU64::new(0);
    let temp = Temporary(std::env::temp_dir().join(format!(
        "glue-macho-edit-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&temp.0).map_err(|e| bad(e.to_string()))?;
    let path = temp.0.join("image");
    fs::copy(source, &path).map_err(|e| bad(e.to_string()))?;
    let original = read_image(source)?;
    let mut args = Vec::new();
    let mut descriptions = Vec::new();
    for (old, new) in edits {
        args.extend(["-change".into(), old.clone(), new.clone()]);
        descriptions.push(format!("dependency {old} -> {new}"));
    }
    if let Some(id) = id {
        args.extend(["-id".into(), id.into()]);
        descriptions.push(format!("dylib ID -> {id}"));
    }
    for rpath in remove {
        args.extend(["-delete_rpath".into(), rpath.clone()]);
        descriptions.push(format!("remove rpath {rpath}"));
    }
    run("/usr/bin/install_name_tool", &args, &path)?;
    run(
        "/usr/bin/codesign",
        &["--force".into(), "--sign".into(), "-".into()],
        &path,
    )?;
    run(
        "/usr/bin/codesign",
        &["--verify".into(), "--strict".into()],
        &path,
    )?;
    let bytes = read_image(&path)?;
    let before = inspect_bytes(&original, None)?;
    let after = inspect_bytes(&bytes, Some(&before.architecture))?;
    for (old, new) in edits {
        if after.dependencies.contains(old) || !after.dependencies.contains(new) {
            return Err(bad(
                "independent Mach-O metadata verification rejected normalization",
            ));
        }
    }
    if before.architecture != after.architecture || before.kind != after.kind {
        return Err(bad("normalization changed image kind/architecture"));
    }
    let change = Transformation {
        path: deployed.into(),
        input: InputIdentity::of(&original),
        output: InputIdentity::of(&bytes),
        edits: descriptions,
        signing: Some(
            "ad_hoc; codesign --verify --strict passed; no Developer ID or notarization claim"
                .into(),
        ),
    };
    Ok((bytes, change))
}
