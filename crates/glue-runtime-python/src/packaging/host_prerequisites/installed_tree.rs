//! Exact selected-content admission; input sources are never evaluated.
use super::*;

const SYSCONFIG: &str = "lib/python3.13/_sysconfigdata__linux_aarch64-linux-gnu.py";
const STOCK: &[u8] =
    include_bytes!("../../../../../fixtures/python-runtime-trees/stock-sysconfig.py");
const UV_TEMPLATE: &[u8] =
    include_bytes!("../../../../../fixtures/python-runtime-trees/uv-0.12.23-sysconfig.py.in");
const TOKEN: &str = "__GLUE_RUNTIME_TREE_ROOT__";
const TEMPLATE_SHA: &str = "ac2bdd1c0d98d36a508b19006c7485e0100585ff3703f090dab6b075017f11fb";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledTreeProvenance {
    pub input_root: String,
    /// Selected source layout, not proof of which installer created the tree.
    pub input_layout: String,
    pub inspection_scope: String,
    pub expected_artifact: ArtifactIdentity,
    pub sysconfig_input: FileIdentity,
    pub sysconfig_output: FileIdentity,
    pub sysconfig_normalized: bool,
    pub sysconfig_template: Option<ContentIdentity>,
}

/// Bound every selected read without consulting the input filesystem.
/// The one relocatable sysconfig source may have either exact admitted spelling.
pub fn installed_tree_input_limits(root: &str) -> Result<BTreeMap<String, u64>, String> {
    validate_prefix(root, HostProvider::InstallOnly)?;
    let expected = expected(HostProvider::InstallOnly)?;
    let uv = uv_source(root, &expected)?;
    let mut limits: BTreeMap<_, _> = expected
        .files
        .into_iter()
        .map(|(p, s)| (p, s.size))
        .collect();
    let maximum = limits
        .get_mut(SYSCONFIG)
        .ok_or("missing pinned sysconfig source")?;
    *maximum = (*maximum).max(uv.len() as u64);
    Ok(limits)
}

/// Own only the pinned prerequisites, admitting two exact sysconfig spellings.
/// Publish stock embedding bytes after an explicitly reported uv normalization.
pub fn installed_tree(
    root: &str,
    mut files: BTreeMap<String, Vec<u8>>,
) -> Result<HostPrerequisites, String> {
    validate_prefix(root, HostProvider::InstallOnly)?;
    let expected = expected(HostProvider::InstallOnly)?;
    if files.len() != expected.files.len() || files.keys().ne(expected.files.keys()) {
        return Err("installed-tree prerequisite inventory differs from its fixed profile".into());
    }
    let uv = uv_source(root, &expected)?;
    let input = &files[SYSCONFIG];
    let normalized = if input == STOCK {
        false
    } else if input == &uv {
        true
    } else {
        return Err(
            "installed-tree sysconfig differs from stock or the exact uv 0.12.23 layout".into(),
        );
    };
    let tree = tree_provenance(root, normalized, &uv, &expected)?;
    if normalized {
        files.insert(SYSCONFIG.into(), STOCK.to_vec());
    }
    validate_owned_files(&files, &expected.files)?;
    let owned = HostPrerequisites {
        files,
        provenance: provenance(&tree, &expected)?,
    };
    validate_contents(&owned)?;
    Ok(owned)
}

fn identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn uv_source(root: &str, expected: &Expected) -> Result<Vec<u8>, String> {
    if expected.files.get(SYSCONFIG) != Some(&identity(STOCK)) {
        return Err("checked-in original sysconfig differs from its stock source pin".into());
    }
    let template =
        std::str::from_utf8(UV_TEMPLATE).map_err(|_| "sysconfig template is not UTF-8")?;
    if UV_TEMPLATE.len() != 51_552
        || digest(UV_TEMPLATE) != TEMPLATE_SHA
        || template.matches(TOKEN).count() != 27
    {
        return Err("checked-in uv sysconfig template identity differs".into());
    }
    // The fixed template uses JSON-compatible double-quoted string literals.
    // Root admission restricts this to ASCII, and serde supplies exact escaping.
    let quoted = serde_json::to_string(root).map_err(|error| error.to_string())?;
    Ok(template
        .replace(TOKEN, &quoted[1..quoted.len() - 1])
        .into_bytes())
}

fn tree_provenance(
    root: &str,
    normalized: bool,
    uv: &[u8],
    expected: &Expected,
) -> Result<InstalledTreeProvenance, String> {
    let pins = Pins::from_json(PINS)?;
    Ok(InstalledTreeProvenance {
        input_root: root.into(),
        input_layout: if normalized {
            "uv-0.12.23-sysconfig"
        } else {
            "stock-install-only"
        }
        .into(),
        inspection_scope: "selected-prerequisites-only".into(),
        expected_artifact: artifact_identity(pins.install_only),
        sysconfig_input: identity(if normalized { uv } else { STOCK }),
        sysconfig_output: expected.files[SYSCONFIG].clone(),
        sysconfig_normalized: normalized,
        sysconfig_template: normalized.then(|| ContentIdentity {
            path: "fixtures/python-runtime-trees/uv-0.12.23-sysconfig.py.in".into(),
            size: UV_TEMPLATE.len() as u64,
            sha256: TEMPLATE_SHA.into(),
        }),
    })
}

pub(super) fn provenance(
    tree: &InstalledTreeProvenance,
    expected: &Expected,
) -> Result<HostPrerequisiteProvenance, String> {
    validate_prefix(&tree.input_root, HostProvider::InstallOnly)?;
    let uv = uv_source(&tree.input_root, expected)?;
    if tree != &tree_provenance(&tree.input_root, tree.sysconfig_normalized, &uv, expected)? {
        return Err("installed-tree provenance differs from its exact selected layout".into());
    }
    let facts = artifact_facts(HostProvider::InstallOnly);
    let mut result = super::provenance(
        HostProvider::InstallOnly,
        expected,
        facts.0,
        facts.1,
        facts.2,
    )?;
    result.artifact = None;
    result.artifact_entries = None;
    result.artifact_payload_bytes = None;
    result.omitted_files = None;
    result.omitted_bytes = None;
    result.installed_tree = Some(tree.clone());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bounds_are_fixed_except_for_the_escaped_root_expansion() {
        let expected = expected(HostProvider::InstallOnly).unwrap();
        for root in [
            "/installed Python",
            "/Python's \"root",
            "/root/__GLUE_RUNTIME_TREE_ROOT__",
        ] {
            let limits = installed_tree_input_limits(root).unwrap();
            assert_eq!(limits.len(), 1041);
            for (path, size) in limits {
                assert_eq!(
                    size,
                    if path == SYSCONFIG {
                        expected.files[&path]
                            .size
                            .max(uv_source(root, &expected).unwrap().len() as u64)
                    } else {
                        expected.files[&path].size
                    }
                );
            }
        }
        assert!(installed_tree_input_limits("relative").is_err());
        assert!(installed_tree_input_limits("/a/../b").is_err());
        assert!(installed_tree_input_limits(&"/a".repeat(62)).is_err());
    }

    #[test]
    fn tree_provenance_has_no_observed_artifact_inventory_or_omission_claim() {
        let expected = expected(HostProvider::InstallOnly).unwrap();
        let uv = uv_source("/selected Python", &expected).unwrap();
        for normalized in [false, true] {
            let tree = tree_provenance("/selected Python", normalized, &uv, &expected).unwrap();
            let report = provenance(&tree, &expected).unwrap();
            assert_eq!(report.artifact, None);
            assert_eq!(report.artifact_entries, None);
            assert_eq!(report.artifact_payload_bytes, None);
            assert_eq!(report.omitted_files, None);
            assert_eq!(report.omitted_bytes, None);
            assert_eq!(report.selected_files, 1041);
            assert_eq!(report.selected_bytes, 89_479_393);
            assert!(!report.runtime_execution_observed);
            assert!(!report.is_complete_python_installation);
            assert_eq!(tree.sysconfig_normalized, normalized);
            assert_eq!(tree.sysconfig_output, identity(STOCK));
            assert_eq!(
                tree.sysconfig_input,
                identity(if normalized { &uv } else { STOCK })
            );
        }
    }

    #[test]
    fn altered_layout_reference_or_normalization_provenance_is_rejected() {
        let expected = expected(HostProvider::InstallOnly).unwrap();
        let uv = uv_source("/selected Python", &expected).unwrap();
        let good = tree_provenance("/selected Python", true, &uv, &expected).unwrap();
        for index in 0..7 {
            let mut tree = good.clone();
            match index {
                0 => tree.input_root.push_str(" changed"),
                1 => tree.input_layout = "another-uv".into(),
                2 => tree.inspection_scope = "complete-tree".into(),
                3 => tree.sysconfig_input.size += 1,
                4 => tree.sysconfig_normalized = false,
                5 => tree.expected_artifact.sha256 = digest(b"wrong artifact"),
                _ => tree.sysconfig_template = None,
            }
            assert!(provenance(&tree, &expected).is_err());
        }
    }

    #[test]
    fn incomplete_owned_inputs_reject_before_any_source_normalization() {
        assert!(
            installed_tree("/installed Python", BTreeMap::new())
                .unwrap_err()
                .contains("inventory")
        );
    }
}
