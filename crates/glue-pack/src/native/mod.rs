//! Build-time native closure inspection. Compact images use the OS loader, not the memory mapper.
pub mod linux;
use crate::distribution::{PayloadSource, Result};
use glue_format::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeFacts {
    pub format: String,
    pub architecture: String,
    pub kind: String,
    pub dependencies: Vec<String>,
    pub identity: Option<String>,
    pub search_paths: Vec<String>,
    pub minimum_os: Option<String>,
    pub versions: BTreeSet<String>,
    pub features: BTreeSet<String>,
    pub interpreter: Option<String>,
}
#[derive(Clone, Debug)]
pub struct NativeSearchRoot {
    pub source: PathBuf,
    pub deployed: String,
    pub provider: DependencyProvider,
}
#[derive(Clone, Debug)]
pub struct NativeRequest {
    pub images: Vec<PathBuf>,
    pub search_roots: Vec<NativeSearchRoot>,
    pub target: String,
    pub normalize: bool,
    pub host_libraries: BTreeSet<String>,
}
#[derive(Clone, Debug, Default)]
pub struct NativeCollection {
    pub payloads: BTreeMap<String, PayloadSource>,
    pub inventory: NativeInventory,
    pub mappings: BTreeMap<PathBuf, String>,
    pub facts: BTreeMap<String, NativeFacts>,
}
pub(crate) fn diagnostic(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "supply a compatible relocatable library in an explicit search root",
    )
}
pub fn inspect(path: &Path) -> Result<NativeFacts> {
    let bytes = read_image(path)?;
    if bytes.starts_with(b"\x7fELF") {
        linux::inspect_bytes(&bytes)
    } else {
        Err(diagnostic(
            DiagnosticCode::UnsupportedCapability,
            format!("{} is not a supported native image", path.display()),
        ))
    }
}
pub(crate) fn read_image(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(path).map_err(|e| {
        diagnostic(
            DiagnosticCode::MissingInput,
            format!("{}: {e}", path.display()),
        )
    })?;
    if f.metadata()
        .map_err(|e| diagnostic(DiagnosticCode::MissingInput, e.to_string()))?
        .len()
        > 512 * 1024 * 1024
    {
        return Err(diagnostic(
            DiagnosticCode::ResourceLimit,
            "native image exceeds 512 MiB",
        ));
    }
    let mut b = Vec::new();
    std::io::Read::take(&mut f, 512 * 1024 * 1024 + 1)
        .read_to_end(&mut b)
        .map_err(|e| diagnostic(DiagnosticCode::MissingInput, e.to_string()))?;
    if b.len() > 512 * 1024 * 1024 {
        return Err(diagnostic(
            DiagnosticCode::ResourceLimit,
            "native image grew beyond bound",
        ));
    }
    Ok(b)
}
fn system_library(name: &str, target: &str) -> bool {
    if target.ends_with("apple-darwin") {
        return name.starts_with("/usr/lib/") || name.starts_with("/System/Library/");
    }
    [
        "libc.so.6",
        "libm.so.6",
        "libdl.so.2",
        "libpthread.so.0",
        "librt.so.1",
        "libresolv.so.2",
        "libutil.so.1",
        "ld-linux-x86-64.so.2",
        "ld-linux-aarch64.so.1",
    ]
    .contains(&name)
}
/// Preserve every input's relative path under declared roots. No host search-path fallback.
pub fn collect(request: &NativeRequest) -> Result<NativeCollection> {
    let arch = if request.target.starts_with("aarch64-") {
        "aarch64"
    } else if request.target.starts_with("x86_64-") {
        "x86_64"
    } else {
        return Err(diagnostic(
            DiagnosticCode::TargetMismatch,
            "unsupported native architecture",
        ));
    };
    let mut roots = Vec::new();
    for root in &request.search_roots {
        let source = fs::canonicalize(&root.source).map_err(|e| {
            diagnostic(
                DiagnosticCode::MissingInput,
                format!("{}: {e}", root.source.display()),
            )
        })?;
        validate_payload_path(&root.deployed)
            .map_err(|e| diagnostic(DiagnosticCode::PathEscape, e.to_string()))?;
        roots.push(NativeSearchRoot {
            source,
            deployed: root.deployed.clone(),
            provider: root.provider.clone(),
        });
    }
    roots.sort_by_key(|r| std::cmp::Reverse(r.source.components().count()));
    let locate = |path: &Path| -> Result<(PathBuf, String, DependencyProvider)> {
        let canonical = fs::canonicalize(path).map_err(|e| {
            diagnostic(
                DiagnosticCode::MissingDependency,
                format!("{}: {e}", path.display()),
            )
        })?;
        let root = roots
            .iter()
            .find(|r| canonical.starts_with(&r.source))
            .ok_or_else(|| {
                diagnostic(
                    DiagnosticCode::PathEscape,
                    format!("{} escapes declared native roots", path.display()),
                )
            })?;
        let relative = canonical
            .strip_prefix(&root.source)
            .unwrap()
            .to_str()
            .ok_or_else(|| diagnostic(DiagnosticCode::PathEscape, "non-UTF8 native path"))?;
        let deployed = format!("{}/{relative}", root.deployed);
        validate_payload_path(&deployed)
            .map_err(|e| diagnostic(DiagnosticCode::PathEscape, e.to_string()))?;
        Ok((canonical, deployed, root.provider.clone()))
    };
    let mut result = NativeCollection::default();
    let mut queue = VecDeque::new();
    for image in &request.images {
        let (source, deployed, _) = locate(image)?;
        result.inventory.roots.insert(deployed.clone(), deployed);
        queue.push_back(source);
    }
    let mut identities: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut link_contracts = BTreeMap::new();
    while let Some(source) = queue.pop_front() {
        if result.mappings.contains_key(&source) {
            continue;
        }
        if result.mappings.len() >= 100_000 {
            return Err(diagnostic(
                DiagnosticCode::ResourceLimit,
                "native closure exceeds 100000 images",
            ));
        }
        let (_, deployed, _) = locate(&source)?;
        let facts = inspect(&source)?;
        if facts.architecture != arch
            || (request.target.contains("linux") != (facts.format == "elf"))
        {
            return Err(diagnostic(
                DiagnosticCode::TargetMismatch,
                format!(
                    "{} is {} {}, expected {}",
                    source.display(),
                    facts.format,
                    facts.architecture,
                    request.target
                ),
            ));
        }
        let bytes = read_image(&source)?;
        let link = linux::inspect_link_contract(&bytes)?;
        result
            .inventory
            .features
            .extend(link.properties.iter().cloned());
        if let Some(floor) = &link.minimum_kernel {
            result
                .inventory
                .host_requirements
                .insert(format!("linux>={floor}"));
        }
        link_contracts.insert(deployed.clone(), link);
        let sha = digest(&bytes);
        if let Some(identity) = &facts.identity {
            if let Some((previous, other)) = identities.get(identity) {
                if previous != &sha {
                    return Err(diagnostic(
                        DiagnosticCode::MissingDependency,
                        format!("conflicting native identity {identity}: {other} and {deployed}"),
                    ));
                }
            }
            identities.insert(identity.clone(), (sha, deployed.clone()));
        }
        result.mappings.insert(source.clone(), deployed.clone());
        result
            .payloads
            .insert(deployed.clone(), PayloadSource::File(source.clone()));
        result
            .inventory
            .features
            .extend(facts.features.iter().cloned());
        result
            .inventory
            .host_requirements
            .extend(facts.versions.iter().cloned());
        if !request.normalize
            && facts
                .search_paths
                .iter()
                .any(|p| !p.starts_with("$ORIGIN") && !p.starts_with("${ORIGIN}"))
        {
            return Err(diagnostic(
                DiagnosticCode::TransformationRequired,
                format!(
                    "{deployed}: absolute/cwd-relative ELF search paths need --normalize-native-paths"
                ),
            ));
        }
        for needed in &facts.dependencies {
            if system_library(needed, &request.target) || request.host_libraries.contains(needed) {
                let provider = if system_library(needed, &request.target) {
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
            let mut candidates = Vec::new();
            let parent = source.parent().unwrap();
            if needed.contains('/')
                && !needed.starts_with("$ORIGIN/")
                && !needed.starts_with("${ORIGIN}/")
            {
                if !request.normalize {
                    return Err(diagnostic(
                        DiagnosticCode::TransformationRequired,
                        format!("{deployed}: dependency {needed} requires explicit normalization"),
                    ));
                }
                if needed.starts_with('/') {
                    candidates.push(PathBuf::from(needed));
                } else {
                    for root in &roots {
                        candidates.push(root.source.join(needed));
                    }
                }
            } else if needed.starts_with("$ORIGIN/") || needed.starts_with("${ORIGIN}/") {
                let expanded = needed
                    .replace("${ORIGIN}", &parent.to_string_lossy())
                    .replace("$ORIGIN", &parent.to_string_lossy());
                candidates.push(PathBuf::from(expanded));
            } else {
                for path in &facts.search_paths {
                    if path.starts_with("$ORIGIN") || path.starts_with("${ORIGIN}") {
                        let expanded = path
                            .replace("${ORIGIN}", &parent.to_string_lossy())
                            .replace("$ORIGIN", &parent.to_string_lossy());
                        candidates.push(PathBuf::from(expanded).join(needed));
                    } else if request.normalize && path.starts_with('/') {
                        candidates.push(PathBuf::from(path).join(needed));
                    } else if request.normalize {
                        for root in &roots {
                            candidates.push(root.source.join(path).join(needed));
                        }
                    }
                }
                if candidates.is_empty() || request.normalize {
                    candidates.push(parent.join(needed));
                    for root in &roots {
                        candidates.push(root.source.join(needed));
                    }
                }
            }
            let existing: Vec<_> = candidates.iter().filter(|p| p.is_file()).collect();
            if existing.is_empty() {
                return Err(diagnostic(
                    DiagnosticCode::MissingDependency,
                    format!(
                        "{} -> {needed}: no image in declared search paths",
                        source.display()
                    ),
                ));
            }
            let selected = existing[0];
            let (resolved, relative, provider) = locate(selected)?;
            if !request.normalize && facts.search_paths.is_empty() && !needed.contains('/') {
                return Err(diagnostic(
                    DiagnosticCode::TransformationRequired,
                    format!(
                        "{} -> {needed}: OS loader has no relative search path; --normalize-native-paths requires a supported explicit edit",
                        source.display()
                    ),
                ));
            }
            // The loader sees symlink aliases; record those without duplicating native bytes.
            let alias = lexical_path(selected);
            if alias != resolved {
                let selected = &alias;
                let root = roots
                    .iter()
                    .find(|r| selected.starts_with(&r.source))
                    .ok_or_else(|| {
                        diagnostic(DiagnosticCode::PathEscape, "dependency alias escapes roots")
                    })?;
                let logical = format!(
                    "{}/{}",
                    root.deployed,
                    selected
                        .strip_prefix(&root.source)
                        .unwrap()
                        .to_string_lossy()
                );
                if logical != relative {
                    let alias_parent = Path::new(&logical).parent().unwrap();
                    let target = relative_path(alias_parent, Path::new(&relative));
                    result
                        .payloads
                        .insert(logical, PayloadSource::Symlink { target });
                }
            }
            result.inventory.edges.push(NativeDependency {
                from: deployed.clone(),
                name: needed.clone(),
                provider,
                resolved: relative,
            });
            queue.push_back(resolved);
        }
        result.facts.insert(deployed, facts);
    }
    for edge in &result.inventory.edges {
        let needs = &link_contracts[&edge.from].version_needs;
        let names = needs
            .get(&edge.name)
            .or_else(|| needs.get(edge.name.rsplit('/').next().unwrap()));
        if let Some(names) = names {
            if matches!(
                edge.provider,
                DependencyProvider::Bundled | DependencyProvider::Runtime
            ) {
                let supplied = &link_contracts[&edge.resolved].version_definitions;
                let missing: Vec<_> = names.difference(supplied).collect();
                if !missing.is_empty() {
                    return Err(diagnostic(
                        DiagnosticCode::RuntimeAbiMismatch,
                        format!(
                            "{} -> {}: selected image lacks symbol versions {missing:?}",
                            edge.from, edge.name
                        ),
                    ));
                }
            } else {
                for name in names {
                    result
                        .inventory
                        .host_requirements
                        .insert(format!("elf-version:{}:{name}", edge.name));
                }
            }
        }
    }
    if request.normalize {
        linux::normalize_collection(&mut result)?;
    }
    result
        .inventory
        .edges
        .sort_by(|a, b| (&a.from, &a.name).cmp(&(&b.from, &b.name)));
    Ok(result)
}
fn relative_path(from: &Path, to: &Path) -> String {
    let a: Vec<_> = from.components().collect();
    let b: Vec<_> = to.components().collect();
    let common = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
    std::iter::repeat_n("..".to_owned(), a.len() - common)
        .chain(
            b[common..]
                .iter()
                .map(|c| c.as_os_str().to_string_lossy().into_owned()),
        )
        .collect::<Vec<_>>()
        .join("/")
}

fn lexical_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => (),
            other => result.push(other.as_os_str()),
        }
    }
    result
}
