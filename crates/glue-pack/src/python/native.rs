//! Python ABI checks and deployed native-image mappings, independent of package IDs.
use super::{discovery::ResolvedEnvironment, inventory::PythonInventory};
use crate::native::{NativeCollection, NativeSearchRoot};
use glue_format::{DependencyProvider, Diagnostic, DiagnosticCode, InputIdentity, RuntimeVersion};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};
fn error(code: DiagnosticCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        "supply existing native inputs compatible with the selected Python ABI and target; no rebuild is attempted",
    )
}

pub fn validate(
    inventory: &PythonInventory,
    environment: &ResolvedEnvironment,
) -> Result<(), Diagnostic> {
    for name in inventory.native_files.keys() {
        if let Some((_, tail)) = name.rsplit_once(".cpython-") {
            let declared = tail.split('-').next().unwrap_or("");
            let expected = format!(
                "{}{}",
                environment.runtime.version[0], environment.runtime.version[1]
            );
            if declared != expected
                || !environment
                    .runtime
                    .extension_suffixes
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
            {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    format!(
                        "native extension {name} does not match selected {}",
                        environment.runtime.soabi
                    ),
                ));
            }
        }
    }
    let version = RuntimeVersion {
        major: environment.runtime.version[0],
        minor: environment.runtime.version[1],
        patch: environment.runtime.version[2],
    };
    for (name, bytes) in &inventory.resources {
        if name.ends_with(".dist-info/METADATA") {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
            glue_runtime_python::packaging::validate_requires_python(text, &version)
                .map_err(|e| error(DiagnosticCode::RuntimeAbiMismatch, format!("{name}: {e}")))?;
        }
        if !name.ends_with(".dist-info/WHEEL") {
            continue;
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|e| error(DiagnosticCode::InvalidConfiguration, e.to_string()))?;
        let tags = text
            .lines()
            .filter_map(|line| line.strip_prefix("Tag: "))
            .collect::<Vec<_>>();
        if tags.is_empty() {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                format!("WHEEL has no compatibility tags: {name}"),
            ));
        }
        if !tags
            .iter()
            .any(|tag| compatible_tag(tag, environment.runtime.version[1]))
        {
            return Err(error(
                DiagnosticCode::RuntimeAbiMismatch,
                format!(
                    "wheel tags do not match selected CPython {}.{}: {name}",
                    environment.runtime.version[0], environment.runtime.version[1]
                ),
            ));
        }
    }
    Ok(())
}

fn compatible_tag(tag: &str, minor: u16) -> bool {
    let pieces = tag.split('-').collect::<Vec<_>>();
    if pieces.len() != 3 {
        return false;
    }
    let expected = format!("cp3{minor}");
    pieces[0].split('.').any(|python| {
        pieces[1].split('.').any(|abi| {
            if abi == "none" {
                return python == "py3"
                    || python == expected
                    || python
                        .strip_prefix("py3")
                        .and_then(|v| v.parse::<u16>().ok())
                        .is_some_and(|minimum| minimum <= minor);
            }
            if abi == "abi3" {
                return python
                    .strip_prefix("cp3")
                    .and_then(|m| m.parse::<u16>().ok())
                    .is_some_and(|minimum| minimum <= minor);
            }
            python == expected && abi == expected
        })
    })
}

pub fn search_roots(
    environment: &ResolvedEnvironment,
    project: &Path,
) -> Result<Vec<NativeSearchRoot>, Diagnostic> {
    let mut roots = vec![NativeSearchRoot {
        source: fs::canonicalize(project)
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?,
        deployed: "native/python/project".into(),
        provider: DependencyProvider::Bundled,
    }];
    for (index, source) in environment.site_packages.iter().enumerate() {
        roots.push(NativeSearchRoot {
            source: fs::canonicalize(source)
                .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?,
            deployed: format!("native/python/site{index}"),
            provider: DependencyProvider::Bundled,
        });
    }
    Ok(roots)
}

pub fn mappings(
    files: &BTreeMap<String, PathBuf>,
    collected: &BTreeMap<PathBuf, String>,
) -> Result<BTreeMap<String, String>, Diagnostic> {
    files
        .iter()
        .map(|(logical, source)| {
            let source = fs::canonicalize(source)
                .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
            let deployed = collected.get(&source).ok_or_else(|| {
                error(
                    DiagnosticCode::MissingDependency,
                    format!("native image was not collected: {logical}"),
                )
            })?;
            Ok((logical.clone(), deployed.clone()))
        })
        .collect()
}

/// Do not add a shared CPython runtime to a process already using a static one.
/// Ordinary Linux wheels leave Python API symbols unresolved; an explicitly
/// linked libpython must instead be the interpreter's own shared dependency.
pub fn validate_runtime_linkage(
    environment: &ResolvedEnvironment,
    files: &BTreeMap<String, PathBuf>,
) -> Result<(), Diagnostic> {
    let runtime = crate::native::inspect(&environment.runtime.executable)?;
    let runtime_cores = runtime
        .dependencies
        .iter()
        .filter(|name| is_python_core(name))
        .collect::<Vec<_>>();
    for (name, source) in files {
        let image = crate::native::inspect(source)?;
        for dependency in image
            .dependencies
            .iter()
            .filter(|name| is_python_core(name))
        {
            if runtime_cores.is_empty() {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    format!(
                        "{name} links {dependency}, but the selected interpreter statically owns CPython; loading a second core runtime is unsupported"
                    ),
                ));
            }
            let basename = Path::new(dependency).file_name();
            if !runtime_cores
                .iter()
                .any(|core| Path::new(core).file_name() == basename)
            {
                return Err(error(
                    DiagnosticCode::RuntimeAbiMismatch,
                    format!(
                        "{name} links {dependency}, which differs from the interpreter's shared CPython dependency"
                    ),
                ));
            }
        }
    }
    Ok(())
}
fn is_python_core(name: &str) -> bool {
    name.contains("libpython") || name.ends_with("/Python")
}

/// Hash original runtime seeds and their transitive bundled dependencies.
/// Application-only native images remain application inputs, permitting a
/// rebuild to update application packages without replacing the selected runtime.
pub(crate) fn runtime_input_identities(
    seeds: &[PathBuf],
    collection: &NativeCollection,
) -> Result<BTreeMap<String, InputIdentity>, Diagnostic> {
    let sources = collection
        .mappings
        .iter()
        .map(|(source, deployed)| (deployed.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let mut edges = BTreeMap::<&str, Vec<&str>>::new();
    for edge in &collection.inventory.edges {
        if matches!(
            edge.provider,
            DependencyProvider::Runtime | DependencyProvider::Bundled
        ) {
            edges.entry(&edge.from).or_default().push(&edge.resolved);
        }
    }
    let mut queue = VecDeque::new();
    for seed in seeds {
        let canonical = fs::canonicalize(seed)
            .map_err(|e| error(DiagnosticCode::MissingInput, e.to_string()))?;
        let deployed = collection.mappings.get(&canonical).ok_or_else(|| {
            error(
                DiagnosticCode::MissingDependency,
                format!(
                    "runtime seed missing from native closure: {}",
                    seed.display()
                ),
            )
        })?;
        queue.push_back(deployed.as_str());
    }
    let mut visited = BTreeSet::new();
    let mut inputs = BTreeMap::new();
    while let Some(deployed) = queue.pop_front() {
        if !visited.insert(deployed) {
            continue;
        }
        let source = sources.get(deployed).ok_or_else(|| {
            error(
                DiagnosticCode::MissingDependency,
                format!("runtime dependency missing its original input: {deployed}"),
            )
        })?;
        inputs.insert(
            format!("runtime-native/{deployed}"),
            InputIdentity::of(&crate::native::read_image(source)?),
        );
        if let Some(dependencies) = edges.get(deployed) {
            queue.extend(dependencies.iter().copied());
        }
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_matching_and_stable_abi_without_future_ceiling() {
        assert!(compatible_tag("cp313-cp313-manylinux_2_28_aarch64", 13));
        assert!(compatible_tag("cp311-abi3-macosx_11_0_arm64", 15));
        assert!(compatible_tag("cp399-cp399-any", 99));
        assert!(!compatible_tag("cp314-cp314-any", 13));
        assert!(!compatible_tag("cp314-cp314t-any", 14));
        assert!(compatible_tag("py2.py3-none-any", 14));
    }
    #[test]
    fn runtime_graph_identity_tracks_transitive_dependencies_and_excludes_app_only_inputs() {
        let root = std::env::temp_dir().join(format!("glue runtime graph {}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut collection = NativeCollection::default();
        for name in [
            "runtime/bin/python",
            "runtime/lib/core",
            "native/external/secondary",
            "app/module",
            "app/secondary",
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, name.as_bytes()).unwrap();
            collection
                .mappings
                .insert(fs::canonicalize(path).unwrap(), name.into());
        }
        for (from, to) in [
            ("runtime/bin/python", "runtime/lib/core"),
            ("runtime/lib/core", "native/external/secondary"),
            ("app/module", "app/secondary"),
        ] {
            collection
                .inventory
                .edges
                .push(glue_format::NativeDependency {
                    from: from.into(),
                    name: to.into(),
                    provider: DependencyProvider::Bundled,
                    resolved: to.into(),
                });
        }
        let seeds = vec![root.join("runtime/bin/python")];
        let original = runtime_input_identities(&seeds, &collection).unwrap();
        assert_eq!(original.len(), 3);
        assert!(original.contains_key("runtime-native/native/external/secondary"));
        fs::write(root.join("app/secondary"), b"different app bytes").unwrap();
        assert_eq!(
            original,
            runtime_input_identities(&seeds, &collection).unwrap()
        );
        fs::write(
            root.join("native/external/secondary"),
            b"different selected runtime dependency",
        )
        .unwrap();
        assert_ne!(
            original,
            runtime_input_identities(&seeds, &collection).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
