//! Portable build admission for the pinned distribution-metadata profiles.
//!
//! These functions inspect declarations and owned bytes. They never acquire a
//! provider, start an interpreter or inspect a host Python installation.

use crate::{metadata_profile, profile};
use glue_format::{ArchiveLimits, Manifest, ResourceSpec, digest};
use std::collections::BTreeMap;

pub mod host_prerequisites;
pub mod template;

/// Admit an exact metadata-profile template on any builder platform.
pub fn validate_template(manifest: &Manifest) -> Result<ArchiveLimits, String> {
    let selected = profile::validate(manifest).map_err(|error| error.to_string())?;
    match selected.kind {
        profile::Kind::BundledMetadataApp => Ok(metadata_profile::limits_bundled()),
        profile::Kind::HostMetadataApp | profile::Kind::InstallHostMetadataApp => {
            Ok(metadata_profile::limits_host())
        }
        _ => Err("Python package ingestion requires a pinned distribution-metadata profile".into()),
    }
}

/// Replace only the template's application declaration.
///
/// The selected component name, runtime, target and non-application resources
/// remain exactly those of the admitted template. Provider bytes must still be
/// verified separately before publication.
pub fn application_manifest(
    template: &Manifest,
    app_id: &str,
    entry: &str,
    application_specs: BTreeMap<String, ResourceSpec>,
) -> Result<Manifest, String> {
    validate_template(template)?;
    if application_specs.keys().any(|key| !key.starts_with("app/")) {
        return Err("Python package application resources must remain under app/".into());
    }
    let mut manifest = template.clone();
    manifest.app_id = app_id.into();
    manifest.resources.retain(|key, _| !key.starts_with("app/"));
    manifest.resources.extend(application_specs);
    manifest
        .components
        .get_mut(&manifest.entrypoint)
        .expect("admission established the selected component")
        .entry_point = entry.into();
    validate_template(&manifest)?;
    Ok(manifest)
}

/// Verify the complete owned input map against the final declaration and the
/// runtime's existing metadata-content policy, without provider acquisition.
pub fn validate_application_contents(
    manifest: &Manifest,
    resources: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    validate_template(manifest)?;
    if resources.len() != manifest.resources.len() || resources.keys().ne(manifest.resources.keys())
    {
        return Err("Python package input inventory differs from its manifest".into());
    }
    for (key, spec) in &manifest.resources {
        let bytes = &resources[key];
        if bytes.len() as u64 != spec.size || digest(bytes) != spec.sha256 {
            return Err(format!(
                "Python package input size or SHA-256 differs for {key}"
            ));
        }
    }
    metadata_profile::verify_contents(resources)
}

/// Parse the existing bounded METADATA identity contract. The name is returned
/// normalized; the version keeps the exact declared spelling.
pub fn metadata_identity(metadata: &str) -> Result<(String, String), String> {
    if metadata.len() as u64 > metadata_profile::MAX_METADATA {
        return Err("distribution METADATA exceeds 64 KiB".into());
    }
    metadata_profile::metadata_identity(metadata)
}

/// Parse a distribution directory's normalized name and exact version.
pub fn folder_identity(directory: &str) -> Result<(String, &str), String> {
    metadata_profile::folder_identity(directory)
}

/// Parse at most 256 KiB and 1,024 strict three-column CSV RECORD rows.
pub fn record_rows(record: &str) -> Result<Vec<[String; 3]>, String> {
    if record.len() as u64 > metadata_profile::MAX_RECORD {
        return Err("distribution RECORD exceeds 256 KiB".into());
    }
    metadata_profile::record_rows(record)
}

/// Encode the SHA-256 RECORD field using the runtime's exact URL-safe base64
/// spelling, without padding.
pub fn record_hash(bytes: &[u8]) -> String {
    metadata_profile::record_hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{APP, host, host_source_app_profile, import_profile, source_app_profile};
    use glue_format::{Compression, Provisioning};

    fn spec(bytes: &[u8], compression: Compression) -> ResourceSpec {
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: digest(bytes),
            compression,
        }
    }

    fn application() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (APP.into(), b"import customer\n".to_vec()),
            ("app/python/customer.py".into(), b"answer = 42\n".to_vec()),
            (
                "app/python/customer-1.dist-info/METADATA".into(),
                b"Metadata-Version: 2.3\nName: Customer\nVersion: 1\n".to_vec(),
            ),
            (
                "app/python/customer-1.dist-info/RECORD".into(),
                b"customer.py,,\ncustomer-1.dist-info/METADATA,,\ncustomer-1.dist-info/RECORD,,\n"
                    .to_vec(),
            ),
        ])
    }

    fn specs(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, ResourceSpec> {
        files
            .iter()
            .map(|(key, bytes)| (key.clone(), spec(bytes, Compression::Stored)))
            .collect()
    }

    fn provider_specs() -> BTreeMap<String, ResourceSpec> {
        let mut fixed = host_source_app_profile::fixed_specs();
        fixed.insert(
            metadata_profile::HELPER.into(),
            spec(metadata_profile::BOOTSTRAP, Compression::Deflate),
        );
        fixed
    }

    fn host_template(install: bool) -> Manifest {
        let mut resources = provider_specs();
        resources.extend(specs(&application()));
        host_source_app_profile::manifest_for_build(
            "old.application",
            "selected",
            APP,
            resources,
            &host::Config::parse("/missing build-only Python provider").unwrap(),
            if install {
                metadata_profile::INSTALL_BUILD_ID
            } else {
                metadata_profile::HOST_BUILD_ID
            },
        )
        .unwrap()
    }

    fn bundled_template() -> Manifest {
        let mut resources = source_app_profile::fixed_specs().unwrap();
        resources.extend(specs(&application()));
        resources.insert(
            metadata_profile::HELPER.into(),
            spec(metadata_profile::BOOTSTRAP, Compression::Deflate),
        );
        let mut manifest =
            source_app_profile::manifest_for("old.application", "selected", APP, resources)
                .unwrap();
        let runtime = manifest.runtimes.get_mut("python").unwrap();
        runtime.build_id = metadata_profile::BUNDLED_BUILD_ID.into();
        let Provisioning::Bundled { source, .. } = &mut runtime.provisioning else {
            unreachable!()
        };
        source.variant = "pgo+lto-full/bundled-metadata-apps-v1".into();
        manifest
    }

    fn full_host_contents() -> BTreeMap<String, Vec<u8>> {
        let mut files = application();
        files.insert(
            import_profile::IMPORTER.into(),
            import_profile::BOOTSTRAP.to_vec(),
        );
        files.insert(
            metadata_profile::HELPER.into(),
            metadata_profile::BOOTSTRAP.to_vec(),
        );
        files
    }

    #[test]
    fn portable_application_projection_preserves_each_exact_provider() {
        for template in [
            bundled_template(),
            host_template(false),
            host_template(true),
        ] {
            validate_template(&template).unwrap();
            let entry = "app/new task's [entry].py";
            let files = BTreeMap::from([(entry.into(), b"print(42)\n".to_vec())]);
            let changed =
                application_manifest(&template, "new.application", entry, specs(&files)).unwrap();
            assert_eq!(changed.runtimes, template.runtimes);
            assert_eq!(changed.targets, template.targets);
            assert_eq!(changed.entrypoint, template.entrypoint);
            assert_eq!(changed.components["selected"].entry_point, entry);
            assert_eq!(changed.app_id, "new.application");
            assert!(!changed.resources.contains_key(APP));
            assert_eq!(
                changed
                    .resources
                    .iter()
                    .filter(|(key, _)| !key.starts_with("app/"))
                    .collect::<Vec<_>>(),
                template
                    .resources
                    .iter()
                    .filter(|(key, _)| !key.starts_with("app/"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(template.app_id, "old.application");
        }
    }

    #[test]
    fn rejects_nonmetadata_templates_provider_drift_and_application_collisions() {
        let mut template = host_template(false);
        template.resources.remove(metadata_profile::HELPER);
        template.runtimes.get_mut("python").unwrap().build_id =
            host_source_app_profile::BUILD_ID.into();
        profile::validate(&template).unwrap();
        assert!(
            validate_template(&template)
                .unwrap_err()
                .contains("metadata")
        );
        let mut template = host_template(false);
        template
            .resources
            .get_mut(metadata_profile::HELPER)
            .unwrap()
            .sha256 = digest(b"drift");
        assert!(validate_template(&template).is_err());
        let template = host_template(false);
        for files in [
            BTreeMap::from([("python/replacement.py".into(), b"pass\n".to_vec())]),
            BTreeMap::from([
                (APP.into(), b"pass\n".to_vec()),
                ("app/python/os.py".into(), Vec::new()),
            ]),
            BTreeMap::from([
                (APP.into(), b"pass\n".to_vec()),
                ("app/native.so".into(), Vec::new()),
            ]),
        ] {
            assert!(
                application_manifest(&template, "new.application", APP, specs(&files)).is_err()
            );
        }
    }

    #[test]
    fn contents_verify_provider_bytes_inventory_and_existing_record_policy() {
        let template = host_template(false);
        let files = full_host_contents();
        validate_application_contents(&template, &files).unwrap();
        let mut missing = files.clone();
        missing.remove(import_profile::IMPORTER);
        assert!(validate_application_contents(&template, &missing).is_err());
        let mut altered = files.clone();
        altered.get_mut(metadata_profile::HELPER).unwrap()[0] ^= 1;
        assert!(
            validate_application_contents(&template, &altered)
                .unwrap_err()
                .contains("SHA-256")
        );
        let mut extra = files.clone();
        extra.insert("app/undeclared.py".into(), Vec::new());
        assert!(validate_application_contents(&template, &extra).is_err());
        let mut invalid = files;
        invalid.insert(
            "app/python/customer-1.dist-info/RECORD".into(),
            b"../escape.py,,\n".to_vec(),
        );
        let mut declared = template;
        declared.resources.insert(
            "app/python/customer-1.dist-info/RECORD".into(),
            spec(
                &invalid["app/python/customer-1.dist-info/RECORD"],
                Compression::Stored,
            ),
        );
        assert!(
            validate_application_contents(&declared, &invalid)
                .unwrap_err()
                .contains("invalid RECORD path")
        );
    }

    #[test]
    fn public_metadata_parsers_keep_normalization_quoting_and_bounds() {
        assert_eq!(
            metadata_identity("Name: Customer_Demo\r\nVersion: 1.2\r\n").unwrap(),
            ("customer-demo".into(), "1.2".into())
        );
        assert_eq!(
            folder_identity("Customer.Demo-1.2.dist-info").unwrap(),
            ("customer-demo".into(), "1.2")
        );
        assert_eq!(
            record_rows("\"data,one.txt\",,\r\n").unwrap(),
            vec![["data,one.txt".into(), String::new(), String::new()]]
        );
        assert_eq!(
            record_hash(b""),
            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        assert!(metadata_identity(&"x".repeat(64 * 1024 + 1)).is_err());
        assert!(record_rows(&"x".repeat(256 * 1024 + 1)).is_err());
        assert!(record_rows(&"file,,\n".repeat(1025)).is_err());
        assert!(metadata_identity("Name: customer\nName: other\nVersion: 1\n").is_err());
        assert!(record_rows("\"bad\"quote,,\n").is_err());
    }
}
