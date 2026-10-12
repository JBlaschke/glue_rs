//! Bounded application sources with the unchanged pinned bundled PBS provider.
//!
//! Application resources vary; runtime, startup, importer and stdlib identities
//! do not. Host acquisition and native/bytecode application payloads are outside
//! this profile. This is an import compatibility policy, not a Python sandbox.
#![cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]

use super::*;

pub(super) const BUILD_ID: &str = "pbs-20261009-cpython-3.13.16-pgo-lto-bundled-source-apps-v1";
pub(super) const VARIANT: &str = "pgo+lto-full/bundled-source-apps-v1";
pub(super) const MAX_APP_FILES: usize = 1024;
pub(super) const MAX_APP_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_ENTRY_BYTES: u64 = 64 * 1024;
pub(super) const FROZEN_SIZE: u64 = 139_523;
pub(super) const FROZEN_SHA: &str =
    "6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7";
const RESERVED_APP_IDS: [&str; 5] = [
    "stock-pbs-bootstrap",
    "stock-pbs-host-startup",
    "stock-pbs-archive-imports",
    "stock-pbs-host-archive-imports",
    "stock-pbs-registered-extensions",
];

pub(super) fn limits() -> ArchiveLimits {
    import_profile::limits()
}

/// Fixed provider resources for declaration construction; these declarations
/// alone never establish that a caller has the corresponding input bytes.
pub(super) fn fixed_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let mut specs = import_profile::source_specs()?;
    specs.insert(
        LIBRARY.into(),
        ResourceSpec {
            size: LIBRARY_SIZE,
            sha256: LIBRARY_SHA.into(),
            compression: Compression::Stored,
        },
    );
    specs.insert(
        STDLIB.into(),
        ResourceSpec {
            size: FROZEN_SIZE,
            sha256: FROZEN_SHA.into(),
            compression: Compression::Stored,
        },
    );
    specs.insert(
        import_profile::IMPORTER.into(),
        ResourceSpec {
            size: import_profile::BOOTSTRAP.len() as u64,
            sha256: digest(import_profile::BOOTSTRAP),
            compression: Compression::Deflate,
        },
    );
    Ok(specs)
}

/// Construct the declaration shape without acquiring or reading any provider.
/// Call `admit` to check this profile's application/layout policy as well.
pub(super) fn manifest_for(
    app_id: &str,
    component_id: &str,
    entry: &str,
    resources: BTreeMap<String, ResourceSpec>,
) -> Result<Manifest, String> {
    // The historical constructor validates its fixed app/main.py entry before
    // returning. Build only its provider/target shape with three placeholders,
    // then replace the resource/component maps before validating this profile.
    let placeholder = ResourceSpec {
        size: 0,
        sha256: digest(&[]),
        compression: Compression::Stored,
    };
    let mut manifest = profile_manifest(
        [APP, LIBRARY, STDLIB]
            .into_iter()
            .map(|key| (key.into(), placeholder.clone()))
            .collect(),
        None,
    )?;
    manifest.resources = resources;
    manifest.app_id = app_id.into();
    manifest.entrypoint = component_id.into();
    manifest.components = BTreeMap::from([(
        component_id.into(),
        ComponentSpec {
            runtime: "python".into(),
            entry_point: entry.into(),
            native_modules: BTreeSet::new(),
        },
    )]);
    let runtime = manifest.runtimes.get_mut("python").unwrap();
    runtime.build_id = BUILD_ID.into();
    let Provisioning::Bundled { source, .. } = &mut runtime.provisioning else {
        unreachable!("the fixed base manifest uses the bundled provider")
    };
    source.variant = VARIANT.into();
    manifest.validate().map_err(|error| error.to_string())?;
    Ok(manifest)
}

fn app_identity(app_id: &str) -> Result<(), String> {
    if app_id.is_empty()
        || app_id.len() > 128
        || !app_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("source app identity requires 1..128 ASCII letters, digits, dots, underscores or hyphens".into());
    }
    if RESERVED_APP_IDS.contains(&app_id) {
        return Err("source app identity is reserved by an existing controlled profile".into());
    }
    Ok(())
}

fn app_resource(key: &str) -> Result<(), String> {
    ResourcePath::new(key).map_err(|error| error.to_string())?;
    if !key.starts_with("app/") {
        return Err(format!("source app resource is outside app/: {key}"));
    }
    let lower = key.to_ascii_lowercase();
    if lower.split('/').any(|part| part == "__pycache__") {
        return Err(format!("source app bytecode caches are unsupported: {key}"));
    }
    let filename = lower.rsplit('/').next().unwrap();
    if [
        ".pyc", ".pyo", ".so", ".dll", ".pyd", ".dylib", ".bundle", ".node", ".exe", ".o", ".a",
        ".lib",
    ]
    .iter()
    .any(|suffix| filename.ends_with(suffix))
        || filename.contains(".so.")
    {
        return Err(format!(
            "source app native or bytecode payload is unsupported: {key}"
        ));
    }
    Ok(())
}

/// Portable declaration/layout admission before any application/provider I/O.
/// Empty index placeholders validate ownership without allocating payload bytes.
pub(super) fn admit(manifest: &Manifest) -> Result<(), String> {
    admit_application(manifest, &fixed_specs()?)?;
    let component = &manifest.components[&manifest.entrypoint];
    if *manifest
        != manifest_for(
            &manifest.app_id,
            &manifest.entrypoint,
            &component.entry_point,
            manifest.resources.clone(),
        )?
    {
        return Err("manifest differs from the pinned bundled source app provider contract".into());
    }
    Ok(())
}

/// Shared source-only application policy. Each provider independently admits
/// its exact declarations and supplies only its own fixed archive resources.
pub(super) fn admit_application(
    manifest: &Manifest,
    fixed: &BTreeMap<String, ResourceSpec>,
) -> Result<(), String> {
    manifest.validate().map_err(|error| error.to_string())?;
    app_identity(&manifest.app_id)?;
    if manifest.components.len() != 1 || manifest.runtimes.len() != 1 || manifest.targets.len() != 1
    {
        return Err("source apps require one component, runtime and target".into());
    }
    let component = manifest
        .components
        .get(&manifest.entrypoint)
        .ok_or("source app selected component is missing")?;
    if !component.entry_point.starts_with("app/") || !component.entry_point.ends_with(".py") {
        return Err("source app entry must be a canonical .py resource under app/".into());
    }
    source_entry::launcher(&component.entry_point)?;
    let entry = manifest
        .resources
        .get(&component.entry_point)
        .ok_or("source app entry resource is missing")?;
    if entry.size > MAX_ENTRY_BYTES {
        return Err("source app entry exceeds 64 KiB".into());
    }
    let mut expected = fixed.clone();
    let mut app_paths = BTreeMap::new();
    let mut app_bytes = 0u64;
    for (key, spec) in manifest
        .resources
        .iter()
        .filter(|(key, _)| key.starts_with("app/"))
    {
        app_resource(key)?;
        if spec.size > MAX_FILE_BYTES {
            return Err(format!("source app resource exceeds 4 MiB: {key}"));
        }
        app_bytes = app_bytes
            .checked_add(spec.size)
            .ok_or("source app byte total overflow")?;
        if app_bytes > MAX_APP_BYTES {
            return Err("source app resources exceed 8 MiB combined".into());
        }
        app_paths.insert(key.clone(), Vec::new());
        if app_paths.len() > MAX_APP_FILES {
            return Err("source app resource count exceeds 1024".into());
        }
        expected.insert(key.clone(), spec.clone());
    }
    if manifest.resources != expected {
        return Err(
            "source app provider inventory, identity or compression differs from fixed pins".into(),
        );
    }
    let app_index = imports::Index::new_source_app(&manifest.app_id, app_paths.clone())?;
    app_index.reject_external_collisions(&host_import_profile::runtime_names()?)?;
    for key in fixed.keys().filter(|key| key.starts_with("stdlib/")) {
        app_paths.insert(key.clone(), Vec::new());
    }
    imports::Index::new_source_app(&manifest.app_id, app_paths)?;
    Ok(())
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )),
    allow(dead_code)
)]
pub(super) fn read_archive(mut archive: Archive<File>) -> Result<import_profile::Payload, String> {
    archive
        .check_limits(limits())
        .map_err(|error| error.to_string())?;
    admit(archive.manifest())?;
    let app_id = archive.manifest().app_id.clone();
    let entry = archive.manifest().components[&archive.manifest().entrypoint]
        .entry_point
        .clone();
    let keys: Vec<_> = archive.manifest().resources.keys().cloned().collect();
    let mut resources = BTreeMap::new();
    for key in keys {
        resources.insert(
            key.clone(),
            archive
                .read_resource(&key)
                .map_err(|error| error.to_string())?,
        );
    }
    drop(archive);
    let library = resources
        .remove(LIBRARY)
        .ok_or("source app pinned runtime is missing")?;
    check_library(&library)?;
    let bundle = Bundle::parse(
        &resources
            .remove(STDLIB)
            .ok_or("source app pinned startup is missing")?,
    )?;
    let bootstrap = resources
        .remove(import_profile::IMPORTER)
        .ok_or("source app pinned importer is missing")?;
    Ok(import_profile::Payload {
        library,
        bundle,
        app: source_entry::launcher(&entry)?,
        bootstrap,
        index: imports::Index::new_source_app(&app_id, resources)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(bytes: &[u8]) -> ResourceSpec {
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: digest(bytes),
            compression: Compression::Deflate,
        }
    }
    fn fixture() -> Manifest {
        let mut resources = fixed_specs().unwrap();
        for (key, bytes) in [
            ("app/scripts/start.py", b"print('custom app')\n".as_slice()),
            ("app/python/customer/__init__.py", b"".as_slice()),
            ("app/python/customer/value.py", b"answer = 42\n".as_slice()),
            (
                "app/python/customer/assets/binary.bin",
                b"\0\xff".as_slice(),
            ),
        ] {
            resources.insert(key.into(), spec(bytes));
        }
        manifest_for(
            "customer-report",
            "launch-report",
            "app/scripts/start.py",
            resources,
        )
        .unwrap()
    }
    fn reject(mut manifest: Manifest, change: impl FnOnce(&mut Manifest)) {
        change(&mut manifest);
        assert!(admit(&manifest).is_err());
    }

    #[test]
    fn arbitrary_application_and_component_ids_preserve_provider_pins() {
        let manifest = fixture();
        admit(&manifest).unwrap();
        let decoded = Manifest::from_json(&manifest.to_json().unwrap()).unwrap();
        admit(&decoded).unwrap();
        assert_eq!(decoded.entrypoint, "launch-report");
        assert_eq!(decoded.resources.len(), 2174 + 3 + 4);
        assert_eq!(decoded.runtimes["python"].build_id, BUILD_ID);
        assert!(decoded.host_imports.is_empty() && decoded.native_modules.is_empty());
        assert_eq!(
            crate::profile::validate(&decoded).unwrap().kind,
            crate::profile::Kind::BundledSourceApp
        );
        assert_eq!(
            crate::profile::packaging_limits(&decoded).unwrap(),
            Some(limits())
        );
        let mut stored_app = decoded;
        for (key, spec) in &mut stored_app.resources {
            if key.starts_with("app/") {
                spec.compression = Compression::Stored;
            }
        }
        admit(&stored_app).unwrap();
    }

    #[test]
    fn fixed_runtime_stdlib_importer_and_frozen_identities_reject_drift() {
        let original = fixture();
        for key in [
            LIBRARY,
            STDLIB,
            import_profile::IMPORTER,
            "stdlib/importlib/resources/_common.py",
        ] {
            reject(original.clone(), |manifest| {
                manifest.resources.get_mut(key).unwrap().sha256 = digest(b"changed");
            });
            reject(original.clone(), |manifest| {
                manifest.resources.remove(key);
            });
            reject(original.clone(), |manifest| {
                manifest.resources.get_mut(key).unwrap().size += 1;
            });
            reject(original.clone(), |manifest| {
                let spec = manifest.resources.get_mut(key).unwrap();
                spec.compression = if spec.compression == Compression::Stored {
                    Compression::Deflate
                } else {
                    Compression::Stored
                };
            });
        }
        reject(original, |manifest| {
            manifest
                .resources
                .insert("stdlib/unpinned.py".into(), spec(b""));
        });
    }

    #[test]
    fn existing_profile_ids_and_unsafe_or_oversized_identities_cannot_be_repurposed() {
        for name in RESERVED_APP_IDS {
            assert!(app_identity(name).is_err());
        }
        for name in ["", "app/name", "unicode-ä", "invalid space"] {
            assert!(app_identity(name).is_err());
        }
        assert!(app_identity(&"a".repeat(128)).is_ok());
        assert!(app_identity(&"a".repeat(129)).is_err());
    }

    #[test]
    fn application_entry_must_be_declared_source_under_app() {
        let original = fixture();
        reject(original.clone(), |manifest| {
            manifest
                .components
                .get_mut("launch-report")
                .unwrap()
                .entry_point = "stdlib/codecs.py".into();
        });
        reject(original.clone(), |manifest| {
            manifest.resources.remove("app/scripts/start.py");
        });
        reject(original.clone(), |manifest| {
            manifest
                .resources
                .get_mut("app/scripts/start.py")
                .unwrap()
                .size = MAX_ENTRY_BYTES + 1;
        });
        let mut empty = original;
        empty
            .resources
            .insert("app/scripts/start.py".into(), spec(b""));
        admit(&empty).unwrap();
        let long = format!(
            "app/{}/{}.py",
            vec!["a".repeat(255); 15].join("/"),
            "b".repeat(244)
        );
        ResourcePath::new(&long).unwrap();
        let mut manifest = fixture();
        manifest.resources.insert(long.clone(), spec(b""));
        manifest
            .components
            .get_mut("launch-report")
            .unwrap()
            .entry_point = long;
        assert!(admit(&manifest).is_err());
    }

    #[test]
    fn native_bytecode_cache_and_outside_roots_are_rejected_case_insensitively() {
        for key in [
            "app/helper.PYC",
            "app/helper.pYo",
            "app/library.SO",
            "app/library.so.1.0",
            "app/library.DLL",
            "app/module.PyD",
            "app/library.dylib",
            "app/library.bundle",
            "app/addon.node",
            "app/helper.exe",
            "app/native.o",
            "app/libnative.a",
            "app/libnative.lib",
            "app/__PyCache__/value.py",
            "app/python/customer/__pycache__/value.py",
        ] {
            reject(fixture(), |manifest| {
                manifest.resources.insert(key.into(), spec(b"asset"));
            });
        }
        reject(fixture(), |manifest| {
            manifest
                .resources
                .insert("other/data.bin".into(), spec(b"asset"));
        });
    }

    #[test]
    fn application_count_per_file_and_combined_bytes_are_independently_bounded() {
        reject(fixture(), |manifest| {
            manifest
                .resources
                .get_mut("app/python/customer/assets/binary.bin")
                .unwrap()
                .size = MAX_FILE_BYTES + 1;
        });
        reject(fixture(), |manifest| {
            for i in 0..3 {
                manifest.resources.insert(
                    format!("app/assets/{i}.bin"),
                    ResourceSpec {
                        size: MAX_FILE_BYTES,
                        ..spec(b"asset")
                    },
                );
            }
        });
        reject(fixture(), |manifest| {
            for i in 0..MAX_APP_FILES {
                manifest
                    .resources
                    .insert(format!("app/assets/{i}.bin"), spec(b""));
            }
        });
        let mut boundary = fixture();
        boundary.resources.retain(|key, _| !key.starts_with("app/"));
        boundary
            .resources
            .insert("app/scripts/start.py".into(), spec(b""));
        for i in 0..2 {
            boundary.resources.insert(
                format!("app/assets/{i}.bin"),
                ResourceSpec {
                    size: MAX_FILE_BYTES,
                    ..spec(b"asset")
                },
            );
        }
        admit(&boundary).unwrap();
    }

    #[test]
    fn runtime_roots_and_ambiguous_application_layout_reject_before_payload_reads() {
        for key in [
            "app/python/sys.py",
            "app/python/math.py",
            "app/python/os.py",
            "app/python/__hello__.py",
            "app/python/_glue_archive.py",
            "app/python/_glue_archive_bootstrap.py",
            "app/python/__main__.py",
            "app/python/json/assets.txt",
            "app/python/encodings/__init__.py",
        ] {
            reject(fixture(), |manifest| {
                manifest.resources.insert(key.into(), spec(b""));
            });
        }
        reject(fixture(), |manifest| {
            manifest
                .resources
                .insert("app/python/customer.py".into(), spec(b""));
        });
        reject(fixture(), |manifest| {
            manifest
                .resources
                .insert("app/python/not.importable.py".into(), spec(b""));
        });
        reject(fixture(), |manifest| {
            manifest
                .resources
                .insert("app/python/__init__.py".into(), spec(b""));
        });
    }

    #[test]
    fn host_linked_abi_target_variant_and_mixed_components_do_not_fallback() {
        let original = fixture();
        reject(original.clone(), |manifest| {
            manifest.runtimes.get_mut("python").unwrap().build_id = "another-build".into();
        });
        reject(original.clone(), |manifest| {
            if let Provisioning::Bundled { source, .. } =
                &mut manifest.runtimes.get_mut("python").unwrap().provisioning
            {
                source.variant = "another-variant".into();
            }
        });
        reject(original.clone(), |manifest| {
            manifest.runtimes.get_mut("python").unwrap().provisioning = Provisioning::Host {
                runtime_library: "/host/libpython.so".into(),
                stdlib: "/host/stdlib".into(),
                discovery: HostDiscovery::ExplicitPaths,
            };
        });
        reject(original.clone(), |manifest| {
            let runtime = manifest.runtimes.get_mut("python").unwrap();
            let Provisioning::Bundled {
                provider, source, ..
            } = runtime.provisioning.clone()
            else {
                unreachable!()
            };
            runtime.provisioning = Provisioning::Linked { provider, source };
        });
        reject(original.clone(), |manifest| {
            if let RuntimeAbi::Python { gil, .. } =
                &mut manifest.runtimes.get_mut("python").unwrap().abi
            {
                *gil = GilMode::FreeThreaded;
            }
        });
        reject(original.clone(), |manifest| {
            manifest
                .targets
                .get_mut("linux-arm64")
                .unwrap()
                .page_sizes
                .insert(16384);
        });
        reject(original, |manifest| {
            manifest.components.insert(
                "another".into(),
                manifest.components["launch-report"].clone(),
            );
        });
    }

    #[test]
    fn declared_native_and_host_images_are_rejected_even_with_opaque_asset_names() {
        let mut native = fixture();
        native
            .resources
            .insert("app/assets/image.bin".into(), spec(b"native image"));
        native.native_modules.insert(
            "extension".into(),
            NativeModuleSpec {
                target: "linux-arm64".into(),
                resource: "app/assets/image.bin".into(),
                format: NativeFormat::Elf,
                namespace: "python".into(),
                runtime: Some("python".into()),
                dependencies: vec![DependencySpec::Runtime {
                    runtime: "python".into(),
                }],
                required_features: BTreeSet::from([LoaderFeature::FunctionExports]),
            },
        );
        native
            .components
            .get_mut("launch-report")
            .unwrap()
            .native_modules
            .insert("extension".into());
        native.validate().unwrap();
        assert!(admit(&native).is_err());

        let mut host = fixture();
        host.host_imports.insert(
            "extension".into(),
            HostImportSpec::HostModule {
                target: "linux-arm64".into(),
                path: "/missing/extension.so".into(),
                runtime: Some("python".into()),
                sha256: Some(digest(b"host image")),
            },
        );
        host.validate().unwrap();
        assert!(admit(&host).is_err());
    }

    #[test]
    fn packaging_exception_does_not_relax_other_builds_or_invalid_source_declarations() {
        let valid = fixture();
        assert!(crate::profile::packaging_limits(&valid).unwrap().is_some());
        let mut other = valid.clone();
        other.runtimes.get_mut("python").unwrap().build_id =
            "pbs-20261009-cpython-3.13.16-pgo-lto-archive-imports-v1".into();
        assert_eq!(crate::profile::packaging_limits(&other).unwrap(), None);
        assert!(
            crate::profile::validate(&other)
                .unwrap_err()
                .is_unsupported()
        );
        let mut drift = valid.clone();
        drift.resources.get_mut(LIBRARY).unwrap().sha256 = digest(b"other library");
        assert!(
            !crate::profile::packaging_limits(&drift)
                .unwrap_err()
                .is_unsupported()
        );
        let mut reserved = valid;
        reserved.app_id = "stock-pbs-archive-imports".into();
        assert!(crate::profile::validate(&reserved).is_err());
        assert!(crate::profile::packaging_limits(&reserved).is_err());
    }
}
