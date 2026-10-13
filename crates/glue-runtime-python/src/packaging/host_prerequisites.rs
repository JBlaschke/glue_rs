//! Owned build-time prerequisites for the two admitted pinned host providers.
//!
//! Inputs are inspected as data. The resulting projection is an embedding
//! prerequisite tree, without an interpreter executable or a general-purpose
//! Python installation. This module never consults host paths or starts Python.

use super::template::{ArtifactIdentity, ContentIdentity, HostProvider, InventoryIdentity};
use crate::{PINS, bundle, host, import_profile, metadata_profile};
use glue_format::{digest, validate_resource_paths};
use glue_pbs::{
    ArtifactReport,
    archive::{Entry, EntryKind, MAX_SELECTED_BYTES},
    pins::{ArtifactPin, Pins},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};

const LIBRARY: &str = "lib/libpython3.13.so.1.0";
const STDLIB: &str = "lib/python3.13/";
const LIBRARY_BYTES: u64 = 73_563_968;
const STOCK_MTIME: u64 = 1_704_067_200;
const INSTALL_SOURCE_PINS: &[u8] =
    include_bytes!("../../../../fixtures/python-install-host-source-apps/source-pins.json");
const INSTALL_CACHE_PINS: &[u8] =
    include_bytes!("../../../../fixtures/python-install-host-source-apps/cache-pins.json");

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileIdentity {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug)]
pub struct HostPrerequisites {
    /// Canonical relative paths within the new host prefix.
    pub files: BTreeMap<String, Vec<u8>>,
    pub provenance: HostPrerequisiteProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostPrerequisiteProvenance {
    pub schema_version: u32,
    pub provider: String,
    pub files: BTreeMap<String, FileIdentity>,
    pub artifact: ArtifactIdentity,
    /// Includes regular files, directories and links in the complete artifact.
    pub artifact_entries: usize,
    /// Sum of every regular payload size in the complete artifact.
    pub artifact_payload_bytes: u64,
    pub selected_files: usize,
    pub selected_bytes: u64,
    /// Counts unselected regular files, excluding directory and link entries.
    pub omitted_files: usize,
    pub omitted_bytes: u64,
    pub source_inventory: InventoryIdentity,
    pub cache_inventory: Option<InventoryIdentity>,
    pub profile_build_id: String,
    pub python_version: String,
    pub target_triple: String,
    pub full_install_pairing_observed: bool,
    pub runtime_execution_observed: bool,
    pub is_complete_python_installation: bool,
    pub stock_mtime_seconds: u64,
}

/// Validate the selected profile's existing prefix and retained-owner budgets.
/// This performs declaration validation only, without filesystem discovery.
pub fn validate_prefix(prefix: &str, provider: HostProvider) -> Result<(), String> {
    let config = host::Config::parse(prefix)?;
    match provider {
        HostProvider::Full => config.validate_source_snapshot_layout(),
        HostProvider::InstallOnly => config.validate_install_source_snapshot_layout(),
    }
}

/// Inspect the exact full distribution and own its library/source prerequisites.
pub fn full<R: Read + Seek>(input: &mut R) -> Result<HostPrerequisites, String> {
    let provider = HostProvider::Full;
    let expected = expected(provider)?;
    let selection = selection(provider, &expected.files);
    let pins = Pins::from_json(PINS)?;
    let selected = glue_pbs::inspect_full_selected(&pins, input, &selection, MAX_SELECTED_BYTES)?;
    finish(provider, selected.inspection.full, selected.files, expected)
}

/// Inspect the independently pinned install-only distribution and own its
/// library, sources and three stock encoding caches. No full distribution is
/// inspected, and no new full/install metadata-pairing claim is made.
pub fn install<R: Read + Seek>(input: &mut R) -> Result<HostPrerequisites, String> {
    let provider = HostProvider::InstallOnly;
    let expected = expected(provider)?;
    let selection = selection(provider, &expected.files);
    let pins = Pins::from_json(PINS)?;
    let selected =
        glue_pbs::inspect_install_selected(&pins, input, &selection, MAX_SELECTED_BYTES)?;
    finish(provider, selected.artifact, selected.files, expected)
}

/// Recheck the complete owned map and fixed provenance before publication.
/// Public callers cannot alter a prerequisite or provider identity silently.
pub fn validate_contents(owned: &HostPrerequisites) -> Result<(), String> {
    let provider = match owned.provenance.provider.as_str() {
        "host-full" => HostProvider::Full,
        "host-install" => HostProvider::InstallOnly,
        _ => return Err("host prerequisites require an admitted provider".into()),
    };
    let expected = expected(provider)?;
    let facts = artifact_facts(provider);
    let provenance = provenance(provider, &expected, facts.0, facts.1, facts.2)?;
    if owned.provenance != provenance {
        return Err("host prerequisite provenance differs from its fixed profile".into());
    }
    validate_owned_files(&owned.files, &expected.files)
}

struct Expected {
    files: BTreeMap<String, FileIdentity>,
    sources: BTreeMap<String, FileIdentity>,
    caches: BTreeMap<String, FileIdentity>,
    source_inventory: InventoryIdentity,
    cache_inventory: Option<InventoryIdentity>,
}

fn expected(provider: HostProvider) -> Result<Expected, String> {
    let (source_raw, source_path, count, total, artifact_sha) = match provider {
        HostProvider::Full => (
            import_profile::SOURCE_PINS,
            "fixtures/python-imports/stdlib-pins.json",
            2174,
            39_158_056,
            bundle::FULL_SHA256,
        ),
        HostProvider::InstallOnly => (
            INSTALL_SOURCE_PINS,
            "fixtures/python-install-host-source-apps/source-pins.json",
            1037,
            15_894_268,
            bundle::INSTALL_ONLY_SHA256,
        ),
    };
    let (sources, source_inventory) =
        inventory(source_raw, source_path, count, total, artifact_sha)?;
    let (caches, cache_inventory) = inventory(
        INSTALL_CACHE_PINS,
        "fixtures/python-install-host-source-apps/cache-pins.json",
        3,
        21_157,
        bundle::INSTALL_ONLY_SHA256,
    )?;
    let cache_json: serde_json::Value =
        serde_json::from_slice(INSTALL_CACHE_PINS).map_err(|error| error.to_string())?;
    if cache_json["stock_tar_mtime"] != STOCK_MTIME
        || cache_json["source_inventory_sha256"] != digest(INSTALL_SOURCE_PINS)
    {
        return Err("checked-in host cache producer facts differ".into());
    }
    let mut files: BTreeMap<_, _> = sources
        .iter()
        .map(|(path, spec)| (format!("{STDLIB}{path}"), spec.clone()))
        .collect();
    files.insert(
        LIBRARY.into(),
        FileIdentity {
            size: LIBRARY_BYTES,
            sha256: bundle::RUNTIME_LIBRARY_SHA256.into(),
        },
    );
    let cache_inventory = if provider == HostProvider::InstallOnly {
        for (path, spec) in &caches {
            if files
                .insert(format!("{STDLIB}{path}"), spec.clone())
                .is_some()
            {
                return Err("host cache collides with a source prerequisite".into());
            }
        }
        Some(cache_inventory)
    } else {
        None
    };
    validate_resource_paths(files.keys()).map_err(|error| error.to_string())?;
    let total = payload_bytes(&files)?;
    let (expected_count, expected_bytes) = match provider {
        HostProvider::Full => (2175, 112_722_024),
        HostProvider::InstallOnly => (1041, 89_479_393),
    };
    if files.len() != expected_count || total != expected_bytes || total > MAX_SELECTED_BYTES {
        return Err("host prerequisites differ from the fixed selected-byte budget".into());
    }
    Ok(Expected {
        files,
        sources,
        caches,
        source_inventory,
        cache_inventory,
    })
}

fn inventory(
    raw: &[u8],
    path: &str,
    count: usize,
    total: u64,
    artifact_sha: &str,
) -> Result<(BTreeMap<String, FileIdentity>, InventoryIdentity), String> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    let entries = value["files"]
        .as_object()
        .ok_or("checked-in host inventory lacks files")?;
    let files: BTreeMap<_, _> = entries
        .iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                FileIdentity {
                    size: value["size"]
                        .as_u64()
                        .ok_or("invalid host inventory size")?,
                    sha256: value["sha256"]
                        .as_str()
                        .filter(|sha| {
                            sha.len() == 64
                                && sha.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        })
                        .ok_or("invalid host inventory SHA-256")?
                        .into(),
                },
            ))
        })
        .collect::<Result<_, String>>()?;
    validate_resource_paths(files.keys()).map_err(|error| error.to_string())?;
    if value["schema_version"] != 0
        || value["artifact_sha256"] != artifact_sha
        || files.len() != count
        || payload_bytes(&files)? != total
    {
        return Err("checked-in host inventory differs from the fixed profile".into());
    }
    Ok((
        files,
        InventoryIdentity {
            identity: ContentIdentity {
                path: path.into(),
                size: raw.len() as u64,
                sha256: digest(raw),
            },
            files: count,
            uncompressed_bytes: total,
            artifact_sha256: artifact_sha.into(),
        },
    ))
}

fn member_prefix(provider: HostProvider) -> &'static str {
    match provider {
        HostProvider::Full => "python/install/",
        HostProvider::InstallOnly => "python/",
    }
}

fn selection(provider: HostProvider, files: &BTreeMap<String, FileIdentity>) -> BTreeSet<String> {
    let prefix = member_prefix(provider);
    files.keys().map(|path| format!("{prefix}{path}")).collect()
}

fn finish(
    provider: HostProvider,
    artifact: ArtifactReport,
    selected: BTreeMap<String, Vec<u8>>,
    expected: Expected,
) -> Result<HostPrerequisites, String> {
    verify_projection(&artifact.entries, provider, &expected)?;
    let mut files = BTreeMap::new();
    for (member, bytes) in selected {
        let relative = member
            .strip_prefix(member_prefix(provider))
            .ok_or("selected host prerequisite is outside its installation")?;
        files.insert(relative.into(), bytes);
    }
    validate_owned_files(&files, &expected.files)?;
    let regular_files = artifact
        .entries
        .values()
        .filter(|entry| entry.kind == EntryKind::RegularFile)
        .count();
    let total = artifact
        .entries
        .values()
        .filter(|entry| entry.kind == EntryKind::RegularFile)
        .try_fold(0u64, |total, entry| {
            total
                .checked_add(entry.size)
                .ok_or("host artifact payload total overflows")
        })?;
    let pins = Pins::from_json(PINS)?;
    let pin = match provider {
        HostProvider::Full => &pins.full,
        HostProvider::InstallOnly => &pins.install_only,
    };
    let facts = artifact_facts(provider);
    if artifact_identity(artifact.pin.clone()) != artifact_identity(pin.clone())
        || (artifact.entries.len(), regular_files, total) != facts
    {
        return Err("observed host artifact inventory differs from the pinned profile".into());
    }
    let provenance = provenance(
        provider,
        &expected,
        artifact.entries.len(),
        regular_files,
        total,
    )?;
    let owned = HostPrerequisites { files, provenance };
    validate_contents(&owned)?;
    Ok(owned)
}

fn verify_projection(
    entries: &BTreeMap<String, Entry>,
    provider: HostProvider,
    expected: &Expected,
) -> Result<(), String> {
    let prefix = format!("{}{STDLIB}", member_prefix(provider));
    let mut sources = BTreeMap::new();
    let mut caches = BTreeMap::new();
    for (path, entry) in entries {
        let Some(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        let target = if relative.ends_with(".py") {
            &mut sources
        } else if relative.ends_with(".pyc")
            || relative.ends_with(".pyo")
            || (relative.split('/').any(|part| part == "__pycache__")
                && entry.kind != EntryKind::Directory)
        {
            &mut caches
        } else {
            continue;
        };
        if entry.kind != EntryKind::RegularFile {
            return Err("host source/cache projection contains a nonregular candidate".into());
        }
        target.insert(
            relative.into(),
            FileIdentity {
                size: entry.size,
                sha256: entry
                    .sha256
                    .clone()
                    .ok_or("host artifact file lacks SHA-256")?,
            },
        );
    }
    // Full archives contain these same three stock caches, but the full-source
    // host profile deliberately owns none. Auditing input bytes does not copy
    // them into the full provider's cache-free prerequisite tree.
    if sources != expected.sources || caches != expected.caches {
        return Err(
            "host artifact source/cache projection differs from its pinned inventory".into(),
        );
    }
    Ok(())
}

fn validate_owned_files(
    files: &BTreeMap<String, Vec<u8>>,
    expected: &BTreeMap<String, FileIdentity>,
) -> Result<(), String> {
    if files.len() != expected.len() || files.keys().ne(expected.keys()) {
        return Err("host prerequisite inventory differs from its fixed profile".into());
    }
    for (path, bytes) in files {
        let spec = &expected[path];
        if bytes.len() as u64 != spec.size || digest(bytes) != spec.sha256 {
            return Err(format!("host prerequisite size or SHA-256 differs: {path}"));
        }
    }
    Ok(())
}

fn artifact_facts(provider: HostProvider) -> (usize, usize, u64) {
    // Complete inventories independently retained with the existing compressed
    // pins in docs/evidence/pbs-linux-arm64-inspection-2026-10-09/inspection.json.gz.
    match provider {
        HostProvider::Full => (6574, 5525, 395_119_171),
        HostProvider::InstallOnly => (4526, 3478, 182_155_939),
    }
}

fn provenance(
    provider: HostProvider,
    expected: &Expected,
    entries: usize,
    regular_files: usize,
    total: u64,
) -> Result<HostPrerequisiteProvenance, String> {
    let pins = Pins::from_json(PINS)?;
    let (name, build_id, pin) = match provider {
        HostProvider::Full => ("host-full", metadata_profile::HOST_BUILD_ID, pins.full),
        HostProvider::InstallOnly => (
            "host-install",
            metadata_profile::INSTALL_BUILD_ID,
            pins.install_only,
        ),
    };
    let selected_bytes = payload_bytes(&expected.files)?;
    Ok(HostPrerequisiteProvenance {
        schema_version: 0,
        provider: name.into(),
        files: expected.files.clone(),
        artifact: artifact_identity(pin),
        artifact_entries: entries,
        artifact_payload_bytes: total,
        selected_files: expected.files.len(),
        selected_bytes,
        omitted_files: regular_files
            .checked_sub(expected.files.len())
            .ok_or("host artifact contains too few regular files")?,
        omitted_bytes: total
            .checked_sub(selected_bytes)
            .ok_or("host artifact contains too few payload bytes")?,
        source_inventory: expected.source_inventory.clone(),
        cache_inventory: expected.cache_inventory.clone(),
        profile_build_id: build_id.into(),
        python_version: bundle::PYTHON_VERSION.into(),
        target_triple: bundle::TARGET_TRIPLE.into(),
        full_install_pairing_observed: false,
        runtime_execution_observed: false,
        is_complete_python_installation: false,
        stock_mtime_seconds: STOCK_MTIME,
    })
}

fn artifact_identity(pin: ArtifactPin) -> ArtifactIdentity {
    ArtifactIdentity {
        filename: pin.filename,
        size: pin.size,
        sha256: pin.sha256,
        url: pin.url,
    }
}

fn payload_bytes(files: &BTreeMap<String, FileIdentity>) -> Result<u64, String> {
    files.values().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| "host prerequisite payload total overflows".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fixed_projections_match_existing_profiles_and_exclude_runtime_executables() {
        let full = expected(HostProvider::Full).unwrap();
        let install = expected(HostProvider::InstallOnly).unwrap();
        assert_eq!(full.files.len(), 2175);
        assert_eq!(payload_bytes(&full.files).unwrap(), 112_722_024);
        assert_eq!(install.files.len(), 1041);
        assert_eq!(payload_bytes(&install.files).unwrap(), 89_479_393);
        assert_eq!(full.files[LIBRARY], install.files[LIBRARY]);
        for (path, identity) in &install.sources {
            assert_eq!(full.sources.get(path), Some(identity));
        }
        assert_eq!(full.cache_inventory, None);
        assert_eq!(install.cache_inventory.as_ref().unwrap().files, 3);
        assert!(!full.files.keys().any(|path| path.contains("__pycache__")));
        for projection in [&full, &install] {
            assert!(projection.files.keys().all(|path| {
                path == LIBRARY
                    || (path.starts_with(STDLIB)
                        && (path.ends_with(".py") || path.ends_with(".pyc")))
            }));
            assert!(
                projection
                    .files
                    .keys()
                    .all(|path| !path.starts_with("bin/"))
            );
        }
    }

    #[test]
    fn prefix_validation_reuses_declared_layout_and_distinct_owner_budgets() {
        for provider in [HostProvider::Full, HostProvider::InstallOnly] {
            validate_prefix("/absent build-only Python's [provider]", provider).unwrap();
            for prefix in ["/", "relative", "/a/../b", "/a/", "/a//b", "/caf\u{e9}"] {
                assert!(
                    validate_prefix(prefix, provider).is_err(),
                    "accepted {prefix:?}"
                );
            }
            assert!(validate_prefix(&format!("/{}", "a".repeat(4060)), provider).is_err());
        }
        validate_prefix(&"/a".repeat(52), HostProvider::Full).unwrap();
        assert!(validate_prefix(&"/a".repeat(53), HostProvider::Full).is_err());
        validate_prefix(&"/a".repeat(61), HostProvider::InstallOnly).unwrap();
        assert!(validate_prefix(&"/a".repeat(62), HostProvider::InstallOnly).is_err());
    }

    fn sample_projection() -> Expected {
        let identity = FileIdentity {
            size: 1,
            sha256: digest(b"x"),
        };
        Expected {
            files: BTreeMap::new(),
            sources: BTreeMap::from([("package/source.py".into(), identity.clone())]),
            caches: BTreeMap::from([("encodings/__pycache__/stock.pyc".into(), identity)]),
            source_inventory: expected(HostProvider::Full).unwrap().source_inventory,
            cache_inventory: None,
        }
    }

    fn sample_entries(provider: HostProvider, expected: &Expected) -> BTreeMap<String, Entry> {
        let prefix = format!("{}{STDLIB}", member_prefix(provider));
        expected
            .sources
            .iter()
            .chain(&expected.caches)
            .map(|(path, identity)| {
                (
                    format!("{prefix}{path}"),
                    Entry {
                        kind: EntryKind::RegularFile,
                        size: identity.size,
                        mode: 0o644,
                        sha256: Some(identity.sha256.clone()),
                        link_target: None,
                        resolved_target: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn source_cache_inventory_rejects_missing_extra_altered_or_aliased_candidates() {
        let expected = sample_projection();
        for provider in [HostProvider::Full, HostProvider::InstallOnly] {
            let good = sample_entries(provider, &expected);
            verify_projection(&good, provider, &expected).unwrap();
            let prefix = format!("{}{STDLIB}", member_prefix(provider));
            for path in ["package/source.py", "encodings/__pycache__/stock.pyc"] {
                let path = format!("{prefix}{path}");
                let mut missing = good.clone();
                missing.remove(&path);
                assert!(verify_projection(&missing, provider, &expected).is_err());
                let mut altered = good.clone();
                altered.get_mut(&path).unwrap().sha256 = Some(digest(b"y"));
                assert!(verify_projection(&altered, provider, &expected).is_err());
                let mut alias = good.clone();
                alias.get_mut(&path).unwrap().kind = EntryKind::Symlink;
                assert!(verify_projection(&alias, provider, &expected).is_err());
            }
            for path in [
                "extra.py",
                "extra.pyc",
                "deep/__pycache__/extra.data",
                "extra.pyo",
            ] {
                let mut extra = good.clone();
                extra.insert(
                    format!("{prefix}{path}"),
                    good.values().next().unwrap().clone(),
                );
                assert!(verify_projection(&extra, provider, &expected).is_err());
            }
        }
    }

    #[test]
    fn owned_file_validation_checks_both_inventory_and_complete_payload_identity() {
        let mut files = BTreeMap::from([("lib/python3.13/module.py".into(), b"x".to_vec())]);
        let expected = BTreeMap::from([(
            "lib/python3.13/module.py".into(),
            FileIdentity {
                size: 1,
                sha256: digest(b"x"),
            },
        )]);
        validate_owned_files(&files, &expected).unwrap();
        files.values_mut().next().unwrap()[0] ^= 1;
        assert!(
            validate_owned_files(&files, &expected)
                .unwrap_err()
                .contains("SHA-256")
        );
        files.insert("lib/python3.13/unreviewed.py".into(), Vec::new());
        assert!(
            validate_owned_files(&files, &expected)
                .unwrap_err()
                .contains("inventory")
        );
        files.clear();
        assert!(validate_owned_files(&files, &expected).is_err());
    }

    #[test]
    fn provenance_binds_observed_artifact_omissions_and_makes_no_execution_claim() {
        for provider in [HostProvider::Full, HostProvider::InstallOnly] {
            let expected = expected(provider).unwrap();
            let facts = artifact_facts(provider);
            let first = provenance(provider, &expected, facts.0, facts.1, facts.2).unwrap();
            let repeated = provenance(provider, &expected, facts.0, facts.1, facts.2).unwrap();
            assert_eq!(first, repeated);
            assert_eq!(first.selected_files + first.omitted_files, facts.1);
            assert_eq!(first.selected_bytes + first.omitted_bytes, facts.2);
            assert_eq!(first.files, expected.files);
            assert!(!first.full_install_pairing_observed);
            assert!(!first.runtime_execution_observed);
            assert!(!first.is_complete_python_installation);
            assert_eq!(first.stock_mtime_seconds, STOCK_MTIME);
            let template = super::super::template::host("/unavailable Python", provider).unwrap();
            assert_eq!(
                first.profile_build_id,
                template.manifest.runtimes["python"].build_id
            );
            assert_eq!(first.source_inventory, template.provenance.source_inventory);
            assert_eq!(first.cache_inventory, template.provenance.cache_inventory);
        }
    }

    #[test]
    fn public_owned_validation_rejects_provenance_drift_before_publication() {
        let provider = HostProvider::InstallOnly;
        let expected = expected(provider).unwrap();
        let facts = artifact_facts(provider);
        let fixed = provenance(provider, &expected, facts.0, facts.1, facts.2).unwrap();
        for index in 0..10 {
            let mut altered = fixed.clone();
            match index {
                0 => altered.runtime_execution_observed = true,
                1 => altered.full_install_pairing_observed = true,
                2 => altered.is_complete_python_installation = true,
                3 => altered.artifact.sha256 = "0".repeat(64),
                4 => altered.artifact_payload_bytes += 1,
                5 => altered.artifact_entries += 1,
                6 => altered.omitted_files += 1,
                7 => altered.source_inventory.files += 1,
                8 => altered.cache_inventory.as_mut().unwrap().identity.sha256 = "0".repeat(64),
                9 => altered.stock_mtime_seconds += 1,
                _ => unreachable!(),
            }
            let owned = HostPrerequisites {
                files: BTreeMap::new(),
                provenance: altered,
            };
            assert!(
                validate_contents(&owned)
                    .unwrap_err()
                    .contains("provenance")
            );
        }
        let mut unknown = fixed.clone();
        unknown.provider = "system".into();
        assert!(
            validate_contents(&HostPrerequisites {
                files: BTreeMap::new(),
                provenance: unknown
            })
            .is_err()
        );
        assert!(
            validate_contents(&HostPrerequisites {
                files: BTreeMap::new(),
                provenance: fixed
            })
            .unwrap_err()
            .contains("inventory")
        );
    }

    #[test]
    fn constructors_reject_unpinned_inputs_before_materialization() {
        for input in [Vec::new(), b"not a stock PBS artifact".to_vec()] {
            assert!(full(&mut Cursor::new(&input)).unwrap_err().contains("pin"));
            assert!(
                install(&mut Cursor::new(input))
                    .unwrap_err()
                    .contains("pin")
            );
        }
    }
}
