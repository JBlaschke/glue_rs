//! Portable construction of the existing pinned metadata-profile build inputs.
//!
//! Bundled inputs are inspected as data. Host constructors declare a target
//! installation without consulting its filesystem or acquiring a runtime.

use super::{validate_application_contents, validate_template};
use crate::{
    APP, Bundle, LIBRARY, LIBRARY_MEMBER, PINS, STDLIB, bundle, check_library,
    host as host_profile, host_source_app_profile, import_profile, metadata_profile,
    source_app_profile,
};
use glue_format::{Compression, Manifest, Provisioning, ResourceSpec, digest};
use glue_pbs::{
    archive::{Entry, EntryKind},
    pins::Pins,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};

const SOURCE_PREFIX: &str = "python/install/lib/python3.13/";
const APP_ID: &str = "python.runtime.template";
const COMPONENT: &str = "launch";
const PLACEHOLDER: &[u8] = b"raise RuntimeError('This is a Python runtime template; use glue build-python with its manifest.json and root directory to package an application.')\n";
const INSTALL_SOURCE_PINS: &[u8] =
    include_bytes!("../../../../fixtures/python-install-host-source-apps/source-pins.json");
const INSTALL_CACHE_PINS: &[u8] =
    include_bytes!("../../../../fixtures/python-install-host-source-apps/cache-pins.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostProvider {
    Full,
    InstallOnly,
    InstallOnlyStripped,
}

#[derive(Debug)]
pub struct RuntimeTemplate {
    pub manifest: Manifest,
    pub resources: BTreeMap<String, Vec<u8>>,
    pub provenance: TemplateProvenance,
}

/// Input identities and fixed declarations, without an execution claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TemplateProvenance {
    pub schema_version: u32,
    pub provider: String,
    pub host_prefix: Option<String>,
    pub host_prerequisites_verified: bool,
    pub runtime_execution_observed: bool,
    /// A separate image identity when the selected host image differs from the
    /// original full-distribution producer described below.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_runtime_image: Option<ContentIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_runtime_artifact: Option<ArtifactIdentity>,
    /// Only bundled construction inspects an upstream artifact.
    pub inspected_artifact: Option<ArtifactIdentity>,
    pub inspected_artifact_entries: Option<usize>,
    pub frozen_bootstrap: Option<ContentIdentity>,
    pub producer: ProducerFacts,
    /// The checked-in expected inventory; a host's files remain unverified.
    pub source_inventory: InventoryIdentity,
    pub cache_inventory: Option<InventoryIdentity>,
    pub selected_stdlib_sources: usize,
    pub manifest_sha256: String,
    pub resources: BTreeMap<String, ResourceSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentIdentity {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactIdentity {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryIdentity {
    pub identity: ContentIdentity,
    pub files: usize,
    pub uncompressed_bytes: u64,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProducerFacts {
    pub release: String,
    pub revision: String,
    pub python_version: String,
    pub target_triple: String,
    pub build_options: String,
    pub gil: String,
    pub debug: bool,
    pub runtime_library_sha256: String,
    pub metadata_sha256: String,
    pub executable_sha256: String,
    pub bytecode_magic: String,
    pub cache_tag: String,
}

/// Prepare the exact bundled metadata profile from pinned build-time inputs.
///
/// The complete frozen identity validates before reading the PBS stream. The
/// inspector validates the entire compressed artifact and tar inventory before
/// returning selected library/source bytes. No target Python code is executed.
pub fn bundled<R: Read + Seek>(full: &mut R, frozen: &[u8]) -> Result<RuntimeTemplate, String> {
    if frozen.len() as u64 != source_app_profile::FROZEN_SIZE
        || digest(frozen) != source_app_profile::FROZEN_SHA
    {
        return Err(
            "frozen bootstrap size or SHA-256 differs from the pinned runtime template".into(),
        );
    }
    let frozen_bundle = Bundle::parse(frozen)?;
    let sources = import_profile::source_specs()?;
    let source_selection: BTreeSet<_> = sources
        .keys()
        .map(|key| format!("{SOURCE_PREFIX}{}", key.strip_prefix("stdlib/").unwrap()))
        .collect();
    let mut selection = source_selection.clone();
    selection.insert(LIBRARY_MEMBER.into());
    let pins = Pins::from_json(PINS)?;
    let selected = glue_pbs::inspect_full_selected(&pins, full, &selection, 128 * 1024 * 1024)?;
    frozen_bundle.validate_sources(&selected.inspection)?;
    verify_source_projection(&selected.inspection.full.entries, &source_selection)?;
    if selected.files.keys().cloned().collect::<BTreeSet<_>>() != selection {
        return Err("selected PBS runtime template payload inventory differs".into());
    }

    let mut resources = helper_resources();
    let fixed = source_app_profile::fixed_specs()?;
    for (member, bytes) in selected.files {
        let key = if member == LIBRARY_MEMBER {
            check_library(&bytes)?;
            LIBRARY.into()
        } else {
            format!(
                "stdlib/{}",
                member
                    .strip_prefix(SOURCE_PREFIX)
                    .ok_or("unexpected selected PBS template member")?
            )
        };
        let spec = fixed.get(&key).ok_or("unreviewed PBS template resource")?;
        if bytes.len() as u64 != spec.size || digest(&bytes) != spec.sha256 {
            return Err(format!(
                "pinned PBS runtime template identity differs: {key}"
            ));
        }
        resources.insert(key, bytes);
    }
    resources.insert(STDLIB.into(), frozen.to_vec());
    let mut specs = fixed;
    specs.insert(
        metadata_profile::HELPER.into(),
        specification(metadata_profile::BOOTSTRAP, Compression::Deflate),
    );
    specs.insert(APP.into(), specification(PLACEHOLDER, Compression::Stored));
    let mut manifest = source_app_profile::manifest_for(APP_ID, COMPONENT, APP, specs)?;
    let runtime = manifest.runtimes.get_mut("python").unwrap();
    runtime.build_id = metadata_profile::BUNDLED_BUILD_ID.into();
    let Provisioning::Bundled { source, .. } = &mut runtime.provisioning else {
        unreachable!("the fixed source constructor selects bundled Python")
    };
    source.variant = "pgo+lto-full/bundled-metadata-apps-v1".into();

    let mut provenance = provenance("bundled", None, false)?;
    provenance.inspected_artifact = Some(ArtifactIdentity {
        filename: pins.full.filename,
        size: pins.full.size,
        sha256: pins.full.sha256,
        url: pins.full.url,
    });
    provenance.inspected_artifact_entries = Some(selected.inspection.full.entries.len());
    provenance.frozen_bootstrap = Some(identity(STDLIB, frozen));
    provenance.selected_stdlib_sources = sources.len();
    finish(manifest, resources, provenance)
}

/// Declare an exact host provider without inspecting the target installation.
///
/// Prefix and expanded-layout/ownership budgets are validated portably. Actual
/// library, startup, source and cache validation remains runtime work.
pub fn host(prefix: &str, provider: HostProvider) -> Result<RuntimeTemplate, String> {
    let config = host_profile::Config::parse(prefix)?;
    let (name, build_id, install) = match provider {
        HostProvider::Full => {
            config.validate_source_snapshot_layout()?;
            ("host-full", metadata_profile::HOST_BUILD_ID, false)
        }
        HostProvider::InstallOnly => {
            config.validate_install_source_snapshot_layout()?;
            ("host-install", metadata_profile::INSTALL_BUILD_ID, true)
        }
        HostProvider::InstallOnlyStripped => {
            config.validate_install_source_snapshot_layout()?;
            (
                "host-install-stripped",
                metadata_profile::STRIPPED_INSTALL_BUILD_ID,
                true,
            )
        }
    };
    let resources = helper_resources();
    let specs = resources
        .iter()
        .map(|(key, bytes)| {
            (
                key.clone(),
                specification(
                    bytes,
                    if key == APP {
                        Compression::Stored
                    } else {
                        Compression::Deflate
                    },
                ),
            )
        })
        .collect();
    let manifest = host_source_app_profile::manifest_for_build(
        APP_ID, COMPONENT, APP, specs, &config, build_id,
    )?;
    let mut facts = provenance(name, Some(prefix.into()), install)?;
    if provider == HostProvider::InstallOnlyStripped {
        facts.selected_runtime_image = Some(ContentIdentity {
            path: "lib/libpython3.13.so.1.0".into(),
            size: crate::stripped_host::LIBRARY_SIZE,
            sha256: crate::stripped_host::LIBRARY_SHA256.into(),
        });
        let pin = crate::stripped_host::artifact_pin();
        facts.selected_runtime_artifact = Some(ArtifactIdentity {
            filename: pin.filename,
            size: pin.size,
            sha256: pin.sha256,
            url: pin.url,
        });
    }
    finish(manifest, resources, facts)
}

fn helper_resources() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (APP.into(), PLACEHOLDER.to_vec()),
        (
            import_profile::IMPORTER.into(),
            import_profile::BOOTSTRAP.to_vec(),
        ),
        (
            metadata_profile::HELPER.into(),
            metadata_profile::BOOTSTRAP.to_vec(),
        ),
    ])
}

fn verify_source_projection(
    entries: &BTreeMap<String, Entry>,
    expected: &BTreeSet<String>,
) -> Result<(), String> {
    let actual: BTreeSet<_> = entries
        .iter()
        .filter(|(key, entry)| {
            key.starts_with(SOURCE_PREFIX)
                && key.ends_with(".py")
                && entry.kind == EntryKind::RegularFile
        })
        .map(|(key, _)| key.clone())
        .collect();
    if &actual != expected {
        return Err(
            "full PBS runtime template source projection differs from its pinned inventory".into(),
        );
    }
    Ok(())
}

fn provenance(
    provider: &str,
    host_prefix: Option<String>,
    install: bool,
) -> Result<TemplateProvenance, String> {
    let pins = Pins::from_json(PINS)?;
    let source_inventory = if install {
        inventory_identity(
            "fixtures/python-install-host-source-apps/source-pins.json",
            INSTALL_SOURCE_PINS,
            1037,
            15_894_268,
            bundle::INSTALL_ONLY_SHA256,
        )?
    } else {
        inventory_identity(
            "fixtures/python-imports/stdlib-pins.json",
            import_profile::SOURCE_PINS,
            2174,
            39_158_056,
            bundle::FULL_SHA256,
        )?
    };
    let cache_inventory = if install {
        Some(inventory_identity(
            "fixtures/python-install-host-source-apps/cache-pins.json",
            INSTALL_CACHE_PINS,
            3,
            21_157,
            bundle::INSTALL_ONLY_SHA256,
        )?)
    } else {
        None
    };
    Ok(TemplateProvenance {
        schema_version: 0,
        provider: provider.into(),
        host_prefix,
        host_prerequisites_verified: false,
        runtime_execution_observed: false,
        selected_runtime_image: None,
        selected_runtime_artifact: None,
        inspected_artifact: None,
        inspected_artifact_entries: None,
        frozen_bootstrap: None,
        producer: ProducerFacts {
            release: pins.release,
            revision: pins.revision,
            python_version: pins.python_version,
            target_triple: pins.target_triple,
            build_options: pins.build_options,
            gil: "conventional".into(),
            debug: false,
            runtime_library_sha256: bundle::RUNTIME_LIBRARY_SHA256.into(),
            metadata_sha256: bundle::METADATA_SHA256.into(),
            executable_sha256: bundle::EXECUTABLE_SHA256.into(),
            bytecode_magic: "f30d0d0a".into(),
            cache_tag: "cpython-313".into(),
        },
        source_inventory,
        cache_inventory,
        selected_stdlib_sources: 0,
        manifest_sha256: String::new(),
        resources: BTreeMap::new(),
    })
}

fn inventory_identity(
    path: &str,
    bytes: &[u8],
    count: usize,
    total: u64,
    artifact: &str,
) -> Result<InventoryIdentity, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let files = value["files"]
        .as_object()
        .ok_or("invalid checked-in template inventory")?;
    let actual_total = files.values().try_fold(0u64, |sum, file| {
        sum.checked_add(
            file["size"]
                .as_u64()
                .ok_or("invalid checked-in inventory size")?,
        )
        .ok_or("checked-in inventory byte total overflow")
    })?;
    if value["schema_version"] != 0
        || value["artifact_sha256"] != artifact
        || files.len() != count
        || actual_total != total
    {
        return Err("checked-in runtime template inventory differs from the fixed profile".into());
    }
    Ok(InventoryIdentity {
        identity: identity(path, bytes),
        files: count,
        uncompressed_bytes: total,
        artifact_sha256: artifact.into(),
    })
}

fn specification(bytes: &[u8], compression: Compression) -> ResourceSpec {
    ResourceSpec {
        size: bytes.len() as u64,
        sha256: digest(bytes),
        compression,
    }
}

fn identity(path: &str, bytes: &[u8]) -> ContentIdentity {
    ContentIdentity {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn finish(
    manifest: Manifest,
    resources: BTreeMap<String, Vec<u8>>,
    mut provenance: TemplateProvenance,
) -> Result<RuntimeTemplate, String> {
    let limits = validate_template(&manifest)?;
    validate_application_contents(&manifest, &resources)?;
    let bytes = manifest.to_json().map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limits.max_manifest_bytes {
        return Err("runtime template manifest exceeds its selected profile bound".into());
    }
    provenance.manifest_sha256 = digest(&bytes);
    provenance.resources = manifest.resources.clone();
    Ok(RuntimeTemplate {
        manifest,
        resources,
        provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, SeekFrom};

    #[test]
    fn host_templates_match_existing_profiles_and_only_own_helpers_and_placeholder() {
        let prefix = "/absent build-only Python's [provider]";
        for (provider, build_id, source_count) in [
            (HostProvider::Full, metadata_profile::HOST_BUILD_ID, 2174),
            (
                HostProvider::InstallOnly,
                metadata_profile::INSTALL_BUILD_ID,
                1037,
            ),
        ] {
            let template = host(prefix, provider).unwrap();
            assert_eq!(template.manifest.app_id, APP_ID);
            assert_eq!(template.manifest.entrypoint, COMPONENT);
            assert_eq!(template.manifest.components[COMPONENT].entry_point, APP);
            assert_eq!(template.manifest.runtimes["python"].build_id, build_id);
            assert_eq!(template.resources, helper_resources());
            assert_eq!(template.provenance.source_inventory.files, source_count);
            assert!(!template.provenance.host_prerequisites_verified);
            assert!(!template.provenance.runtime_execution_observed);
            assert_eq!(template.provenance.inspected_artifact, None);
            assert_eq!(template.provenance.frozen_bootstrap, None);
            assert_eq!(template.provenance.selected_stdlib_sources, 0);
            assert_eq!(template.provenance.host_prefix.as_deref(), Some(prefix));
            let repeated = host(prefix, provider).unwrap();
            assert_eq!(template.manifest, repeated.manifest);
            assert_eq!(template.provenance, repeated.provenance);
            assert_eq!(template.provenance.resources, template.manifest.resources);
            assert_eq!(
                template.provenance.manifest_sha256,
                digest(&template.manifest.to_json().unwrap())
            );
            let expected = host_source_app_profile::manifest_for_build(
                APP_ID,
                COMPONENT,
                APP,
                template.manifest.resources.clone(),
                &host_profile::Config::parse(prefix).unwrap(),
                build_id,
            )
            .unwrap();
            assert_eq!(template.manifest, expected);
        }
    }

    #[test]
    fn host_construction_checks_expanded_paths_and_distinct_profile_ownership_budgets() {
        for provider in [HostProvider::Full, HostProvider::InstallOnly] {
            for prefix in [
                "/",
                "relative",
                "/a/../b",
                "/a/",
                "/a//b",
                "/a\\b",
                "/a\0b",
                "/caf\u{e9}",
            ] {
                assert!(host(prefix, provider).is_err(), "accepted {prefix:?}");
            }
            assert!(host(&format!("/{}", "a".repeat(4060)), provider).is_err());
        }
        host(&"/a".repeat(52), HostProvider::Full).unwrap();
        assert!(
            host(&"/a".repeat(53), HostProvider::Full)
                .unwrap_err()
                .contains("owners")
        );
        host(&"/a".repeat(61), HostProvider::InstallOnly).unwrap();
        assert!(
            host(&"/a".repeat(62), HostProvider::InstallOnly)
                .unwrap_err()
                .contains("owners")
        );
        host(&"/a".repeat(53), HostProvider::InstallOnly).unwrap();
    }

    #[test]
    fn stripped_template_has_a_distinct_image_and_preserves_producer_and_helpers() {
        let prefix = "/missing declared Python";
        let old = host(prefix, HostProvider::InstallOnly).unwrap();
        let new = host(prefix, HostProvider::InstallOnlyStripped).unwrap();
        assert_eq!(old.resources, new.resources);
        assert_eq!(old.provenance.producer, new.provenance.producer);
        assert_eq!(
            old.provenance.source_inventory,
            new.provenance.source_inventory
        );
        assert_eq!(
            old.provenance.cache_inventory,
            new.provenance.cache_inventory
        );
        assert_eq!(
            new.provenance
                .selected_runtime_image
                .as_ref()
                .unwrap()
                .sha256,
            crate::stripped_host::LIBRARY_SHA256
        );
        assert_eq!(
            new.provenance
                .selected_runtime_artifact
                .as_ref()
                .unwrap()
                .sha256,
            crate::stripped_host::ARTIFACT_SHA256
        );
        assert_eq!(
            new.manifest.runtimes["python"].build_id,
            metadata_profile::STRIPPED_INSTALL_BUILD_ID
        );
        let old_json = serde_json::to_value(old.provenance).unwrap();
        assert!(old_json.get("selected_runtime_image").is_none());
        assert!(old_json.get("selected_runtime_artifact").is_none());
    }

    #[test]
    fn placeholder_is_actionable_and_application_ingestion_replaces_it() {
        let template = host("/missing Python", HostProvider::InstallOnly).unwrap();
        assert!(
            std::str::from_utf8(&template.resources[APP])
                .unwrap()
                .contains("use glue build-python")
        );
        let entry = "app/application.py";
        let application = BTreeMap::from([(
            entry.into(),
            specification(b"print(42)\n", Compression::Stored),
        )]);
        let changed = super::super::application_manifest(
            &template.manifest,
            "customer.application",
            entry,
            application,
        )
        .unwrap();
        assert!(!changed.resources.contains_key(APP));
        assert_eq!(changed.runtimes, template.manifest.runtimes);
        assert_eq!(changed.targets, template.manifest.targets);
        assert_eq!(changed.components[COMPONENT].entry_point, entry);
        assert_eq!(changed.resources.len(), 3);
    }

    #[test]
    fn source_projection_requires_every_expected_regular_source_and_no_extra_sources() {
        let source = format!("{SOURCE_PREFIX}package/module.py");
        let expected = BTreeSet::from([source.clone()]);
        let regular = Entry {
            kind: EntryKind::RegularFile,
            size: 0,
            mode: 0o644,
            sha256: Some(digest(&[])),
            link_target: None,
            resolved_target: None,
        };
        let mut entries = BTreeMap::from([(source.clone(), regular.clone())]);
        verify_source_projection(&entries, &expected).unwrap();
        entries.insert(format!("{SOURCE_PREFIX}unreviewed.py"), regular.clone());
        assert!(verify_source_projection(&entries, &expected).is_err());
        entries.remove(&format!("{SOURCE_PREFIX}unreviewed.py"));
        entries.get_mut(&source).unwrap().kind = EntryKind::Symlink;
        assert!(verify_source_projection(&entries, &expected).is_err());
        entries.clear();
        assert!(verify_source_projection(&entries, &expected).is_err());
    }

    struct ObservedInput {
        touched: bool,
    }

    impl Read for ObservedInput {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.touched = true;
            Err(io::Error::other("unavailable PBS input"))
        }
    }

    impl Seek for ObservedInput {
        fn seek(&mut self, _position: SeekFrom) -> io::Result<u64> {
            self.touched = true;
            Err(io::Error::other("unavailable PBS input"))
        }
    }

    #[test]
    fn complete_frozen_identity_rejects_before_any_upstream_artifact_read() {
        for frozen in [
            Vec::new(),
            vec![b' '; source_app_profile::FROZEN_SIZE as usize],
            vec![0; source_app_profile::FROZEN_SIZE as usize + 1],
        ] {
            let mut input = ObservedInput { touched: false };
            assert!(
                bundled(&mut input, &frozen)
                    .unwrap_err()
                    .contains("frozen bootstrap size or SHA-256")
            );
            assert!(!input.touched);
        }
    }

    #[test]
    fn retained_exact_frozen_bundle_admits_then_inspects_upstream_input() {
        let frozen = include_bytes!(
            "../../../../docs/evidence/pbs-linux-arm64-python-imports-2026-10-10/freeze-bundle.json"
        );
        let mut input = ObservedInput { touched: false };
        assert!(
            bundled(&mut input, frozen)
                .unwrap_err()
                .contains("unavailable PBS input")
        );
        assert!(input.touched);
        let mut altered = frozen.to_vec();
        altered[0] ^= 1;
        input.touched = false;
        assert!(
            bundled(&mut input, &altered)
                .unwrap_err()
                .contains("frozen bootstrap size or SHA-256")
        );
        assert!(!input.touched);
    }
}
