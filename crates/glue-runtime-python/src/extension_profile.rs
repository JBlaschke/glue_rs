//! Bounded registered-initializer experiment, layered on the two source profiles.
//! This is not admission for arbitrary Python extension wheels or host discovery.
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
use glue_native::elf::{self, ElfFacts, SymbolBinding, SymbolKind};

pub(super) const APP_ID: &str = "stock-pbs-registered-extensions";
pub(super) const IMAGE_LIMIT: u64 = 256 * 1024;
pub(super) const DEPENDENCY: &str = "libglue_python_dependency.so";
pub(super) const ROOTS: [&str; 4] = [
    "glue_native_single",
    "glue_native_multi",
    "glue_native_init_error",
    "glue_native_exec_error",
];
pub(super) const PYTHON_IMPORTS: [&str; 8] = [
    "PyLong_FromLong",
    "PyModule_Create2",
    "PyModuleDef_Init",
    "PyModule_GetState",
    "PyModule_AddIntConstant",
    "PyErr_SetString",
    "PyExc_RuntimeError",
    "Py_DecRef",
];
const DEPENDENCY_EXPORT: &str = "glue_python_dependency_answer";

fn names() -> Vec<String> {
    std::iter::once(DEPENDENCY.into())
        .chain(ROOTS.iter().map(|n| format!("{n}.so")))
        .collect()
}
fn native_key(name: &str) -> String {
    format!("native/{name}")
}
fn app() -> Vec<u8> {
    let mut source = import_profile::app_resources().remove(APP).unwrap();
    source.extend_from_slice(b"\n");
    source.extend_from_slice(include_bytes!("../../../fixtures/python-extensions/app.py"));
    source
}
fn app_spec() -> ResourceSpec {
    let source = app();
    ResourceSpec {
        size: source.len() as u64,
        sha256: digest(&source),
        compression: Compression::Deflate,
    }
}
pub(super) fn limits() -> ArchiveLimits {
    import_profile::limits()
}

fn base_manifest(actual: &Manifest) -> Result<(Manifest, Option<host::Config>), String> {
    let mut base = actual.clone();
    base.native_modules.clear();
    base.host_imports.clear();
    base.components
        .get_mut("main")
        .ok_or("missing native app component")?
        .native_modules
        .clear();
    for name in names() {
        base.resources.remove(&native_key(&name));
    }
    let bytes = import_profile::app_resources().remove(APP).unwrap();
    base.resources.insert(
        APP.into(),
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: digest(&bytes),
            compression: Compression::Deflate,
        },
    );
    let is_host = matches!(
        base.runtimes
            .get("python")
            .ok_or("missing native Python runtime")?
            .provisioning,
        Provisioning::Host { .. }
    );
    if is_host {
        base.app_id = "stock-pbs-host-archive-imports".into();
        let config = host_import_profile::admit(&base)?;
        Ok((base, Some(config)))
    } else {
        base.app_id = "stock-pbs-archive-imports".into();
        import_profile::admit(&base)?;
        Ok((base, None))
    }
}

fn overlay(
    base: &Manifest,
    specs: &BTreeMap<String, ResourceSpec>,
    host_dir: Option<&str>,
) -> Result<Manifest, String> {
    if specs.keys().cloned().collect::<Vec<_>>()
        != names()
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    {
        return Err("registered native image inventory differs from the five-image profile".into());
    }
    let mut result = base.clone();
    result.app_id = APP_ID.into();
    result.resources.insert(APP.into(), app_spec());
    for (name, spec) in specs {
        if spec.size == 0 || spec.size > IMAGE_LIMIT || spec.compression != Compression::Stored {
            return Err(
                "native image exceeds its fixed bound or differs from stored profile".into(),
            );
        }
        if let Some(dir) = host_dir {
            host::validate_path(dir)?;
            result.host_imports.insert(
                name.clone(),
                HostImportSpec::HostModule {
                    target: "linux-arm64".into(),
                    path: format!("{dir}/{name}"),
                    runtime: if name == DEPENDENCY {
                        None
                    } else {
                        Some("python".into())
                    },
                    sha256: Some(spec.sha256.clone()),
                },
            );
        } else {
            let dependency = name == DEPENDENCY;
            result.resources.insert(native_key(name), spec.clone());
            result.native_modules.insert(
                name.clone(),
                NativeModuleSpec {
                    target: "linux-arm64".into(),
                    resource: native_key(name),
                    format: NativeFormat::Elf,
                    namespace: "python-registered".into(),
                    runtime: if dependency {
                        None
                    } else {
                        Some("python".into())
                    },
                    dependencies: if dependency {
                        Vec::new()
                    } else {
                        vec![
                            DependencySpec::ArchivedModule {
                                module: DEPENDENCY.into(),
                            },
                            DependencySpec::Runtime {
                                runtime: "python".into(),
                            },
                        ]
                    },
                    required_features: if dependency {
                        BTreeSet::from([LoaderFeature::FunctionExports])
                    } else {
                        BTreeSet::from([LoaderFeature::FunctionExports, LoaderFeature::DataExports])
                    },
                },
            );
            if !dependency {
                result
                    .components
                    .get_mut("main")
                    .unwrap()
                    .native_modules
                    .insert(name.clone());
            }
        }
    }
    result.validate().map_err(|e| e.to_string())?;
    Ok(result)
}

pub(super) fn admit(actual: &Manifest) -> Result<(Option<host::Config>, Option<String>), String> {
    let (base, config) = base_manifest(actual)?;
    let mut specs = BTreeMap::new();
    let mut directory: Option<String> = None;
    if actual.host_imports.is_empty() {
        for name in names() {
            specs.insert(
                name.clone(),
                actual
                    .resources
                    .get(&native_key(&name))
                    .ok_or("missing archived native image")?
                    .clone(),
            );
        }
    } else {
        for name in names() {
            let HostImportSpec::HostModule {
                path,
                sha256: Some(hash),
                ..
            } = actual
                .host_imports
                .get(&name)
                .ok_or("missing explicit native host image")?
            else {
                return Err("native host image must have an explicit path and digest".into());
            };
            let dir = path
                .strip_suffix(&format!("/{name}"))
                .ok_or("native host filename differs from registration profile")?;
            host::validate_path(dir)?;
            if directory.as_deref().is_some_and(|prior| prior != dir) {
                return Err("native host images must use one explicit directory".into());
            }
            directory = Some(dir.into());
            // The manifest's host-import schema has no size. Hash identity is
            // checked before ELF inspection; the open file is independently bounded.
            specs.insert(
                name,
                ResourceSpec {
                    size: 1,
                    sha256: hash.clone(),
                    compression: Compression::Stored,
                },
            );
        }
    }
    if *actual != overlay(&base, &specs, directory.as_deref())? {
        return Err("archive differs from the registered native extension profile".into());
    }
    let reserved = host_import_profile::runtime_names()?;
    if ROOTS.iter().any(|name| reserved.contains(*name)) {
        return Err("native registration shadows a runtime module".into());
    }
    Ok((config, directory))
}

pub(super) fn inspect(name: &str, bytes: &[u8]) -> Result<ElfFacts, String> {
    if bytes.is_empty() || bytes.len() as u64 > IMAGE_LIMIT {
        return Err("native image exceeds 256 KiB".into());
    }
    if !names().iter().any(|expected| expected == name) {
        return Err("unreviewed native image name".into());
    }
    let dependency = name == DEPENDENCY;
    let mut imports: BTreeSet<String> = if dependency {
        BTreeSet::new()
    } else {
        PYTHON_IMPORTS.iter().map(|n| (*n).into()).collect()
    };
    if !dependency {
        imports.insert(DEPENDENCY_EXPORT.into());
    }
    let data = if !dependency && name != "glue_native_multi.so" {
        BTreeSet::from(["PyExc_RuntimeError".into()])
    } else {
        BTreeSet::new()
    };
    let facts =
        elf::inspect_with_data_imports(bytes, name, &imports, &data).map_err(|e| e.to_string())?;
    validate_facts(name, &facts)?;
    Ok(facts)
}

fn validate_facts(name: &str, facts: &ElfFacts) -> Result<(), String> {
    let dependency = name == DEPENDENCY;
    let imports: BTreeSet<String> = PYTHON_IMPORTS
        .iter()
        .map(|n| (*n).into())
        .chain(std::iter::once(DEPENDENCY_EXPORT.into()))
        .collect();
    if facts.symbols.iter().any(|s| {
        s.defined
            && (s.name.starts_with("Py") || s.name.starts_with("_Py"))
            && !s.name.starts_with("PyInit_glue_native_")
    }) {
        return Err("native image defines a selected Python API substitute".into());
    }
    let needed: BTreeSet<_> = facts.needed.iter().map(String::as_str).collect();
    let expected = if dependency {
        BTreeSet::new()
    } else {
        BTreeSet::from([DEPENDENCY, "libpython3.13.so.1.0"])
    };
    if needed != expected
        || facts.needed.len() != expected.len()
        || facts.has_constructors
        || !facts.version_requirements.is_empty()
    {
        return Err("native dependency/constructor/version profile differs".into());
    }
    let export = if dependency {
        DEPENDENCY_EXPORT.into()
    } else {
        format!(
            "PyInit_{}",
            name.strip_suffix(".so")
                .ok_or("native root is not a shared image")?
        )
    };
    let exported: Vec<_> = facts
        .symbols
        .iter()
        .filter(|s| {
            s.defined
                && !s.name.is_empty()
                && s.binding != SymbolBinding::Local
                && s.visibility == 0
        })
        .collect();
    if exported.len() != 1
        || exported[0].name != export
        || exported[0].binding != SymbolBinding::Global
        || exported[0].kind != SymbolKind::Function
        || !facts.contains_executable_address(exported[0].value)
    {
        return Err("native exports differ from the one reviewed function".into());
    }
    for symbol in facts
        .symbols
        .iter()
        .filter(|s| !s.defined && !s.name.is_empty())
    {
        if symbol.binding != SymbolBinding::Global || !imports.contains(&symbol.name) {
            return Err("native weak or undeclared import is unsupported".into());
        }
    }
    Ok(())
}

pub(super) fn prepare(
    base_path: &Path,
    directory: &Path,
    provider: &str,
    output: &Path,
) -> Result<(), String> {
    if !matches!(provider, "archived" | "host") {
        return Err("native provider must be archived or host".into());
    }
    let mut archive =
        Archive::open_with_limits(File::open(base_path).map_err(|e| e.to_string())?, limits())
            .map_err(|e| e.to_string())?;
    let base = archive.manifest().clone();
    if matches!(
        base.runtimes
            .get("python")
            .ok_or("missing Python runtime")?
            .provisioning,
        Provisioning::Host { .. }
    ) {
        host_import_profile::admit(&base)?;
    } else {
        import_profile::admit(&base)?;
    }
    let keys: Vec<_> = base.resources.keys().cloned().collect();
    let mut resources = BTreeMap::new();
    for key in keys {
        resources.insert(
            key.clone(),
            archive.read_resource(&key).map_err(|e| e.to_string())?,
        );
    }
    resources.insert(APP.into(), app());
    let mut specs = BTreeMap::new();
    for name in names() {
        let bytes = bounded_file(&directory.join(&name), IMAGE_LIMIT)?;
        inspect(&name, &bytes)?;
        specs.insert(
            name.clone(),
            ResourceSpec {
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                compression: Compression::Stored,
            },
        );
        if provider == "archived" {
            resources.insert(native_key(&name), bytes);
        }
    }
    let host_dir = if provider == "host" {
        Some(
            directory
                .to_str()
                .ok_or("native host directory must be ASCII")?,
        )
    } else {
        None
    };
    let manifest = overlay(&base, &specs, host_dir)?;
    admit(&manifest)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &manifest, &resources).map_err(|e| e.to_string())?;
    println!("prepared registered native extension fixture ({provider})");
    Ok(())
}

pub(super) fn corrupt(input: &Path, output: &Path) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let bytes = bounded_file(input, limits().max_archive_bytes)?;
    let archive = Archive::open_with_limits(std::io::Cursor::new(&bytes), limits())
        .map_err(|e| e.to_string())?;
    let (_, directory) = admit(archive.manifest())?;
    if directory.is_some() {
        return Err("native corruption control requires archived images".into());
    }
    let entry = &archive.entries()[&native_key(DEPENDENCY)];
    let manifest_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let offset = 64u64
        .checked_add(manifest_len)
        .and_then(|v| v.checked_add(entry.data_offset))
        .ok_or("native offset overflow")?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    out.write_all(&bytes).map_err(|e| e.to_string())?;
    out.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    out.write_all(&[bytes[offset as usize] ^ 1])
        .map_err(|e| e.to_string())?;
    println!("prepared archived native CRC rejection control");
    Ok(())
}

pub(super) struct Image {
    pub name: String,
    pub bytes: Vec<u8>,
    pub facts: ElfFacts,
    pub file: Option<File>,
    pub _directories: Vec<File>,
}
pub(super) enum Runtime {
    Bundled {
        library: Vec<u8>,
        bundle: Box<Bundle>,
    },
    Host(host::Config),
}
pub(super) struct Payload {
    pub runtime: Runtime,
    pub images: Vec<Image>,
    pub app: Vec<u8>,
    pub bootstrap: Vec<u8>,
    pub index: imports::Index,
}

pub(super) fn read(path: &Path) -> Result<Payload, String> {
    let archive = Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, limits())
        .map_err(|e| e.to_string())?;
    read_archive(archive)
}

pub(super) fn read_archive(mut archive: Archive<File>) -> Result<Payload, String> {
    archive.check_limits(limits()).map_err(|e| e.to_string())?;
    let manifest = archive.manifest().clone();
    let (config, directory) = admit(&manifest)?;
    // Verify the complete archive before retaining host files or mapping code.
    let keys: Vec<_> = archive.manifest().resources.keys().cloned().collect();
    let mut resources = BTreeMap::new();
    for key in keys {
        resources.insert(
            key.clone(),
            archive.read_resource(&key).map_err(|e| e.to_string())?,
        );
    }
    drop(archive); // No archive owner survives into any explicit host lookup.
    let mut images = Vec::new();
    for name in names() {
        let (bytes, file, directories) = if let Some(dir) = &directory {
            let path = Path::new(dir).join(&name);
            let HostImportSpec::HostModule {
                sha256: Some(hash), ..
            } = &manifest.host_imports[&name]
            else {
                unreachable!()
            };
            let (mut file, directories) = host::verified_bounded_file(&path, IMAGE_LIMIT, hash)?;
            let size = file.metadata().map_err(|e| e.to_string())?.len();
            let mut bytes = Vec::new();
            (&mut file)
                .take(IMAGE_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 != size || digest(&bytes) != *hash {
                return Err("native host file changed before inspection".into());
            }
            std::io::Seek::rewind(&mut file).map_err(|e| e.to_string())?;
            (bytes, Some(file), directories)
        } else {
            (
                resources
                    .remove(&native_key(&name))
                    .ok_or("missing native bytes")?,
                None,
                Vec::new(),
            )
        };
        let facts = inspect(&name, &bytes)?;
        images.push(Image {
            name,
            bytes,
            facts,
            file,
            _directories: directories,
        });
    }
    let runtime = if let Some(config) = config {
        Runtime::Host(config)
    } else {
        let library = resources
            .remove(LIBRARY)
            .ok_or("missing selected Python library")?;
        check_library(&library)?;
        let bundle = Bundle::parse(
            &resources
                .remove(STDLIB)
                .ok_or("missing frozen startup bundle")?,
        )?;
        Runtime::Bundled {
            library,
            bundle: Box::new(bundle),
        }
    };
    let app = resources.remove(APP).ok_or("missing native app")?;
    let bootstrap = resources
        .remove(import_profile::IMPORTER)
        .ok_or("missing importer")?;
    let index = imports::Index::new(APP_ID, resources)?;
    let natives = ROOTS.iter().map(|s| (*s).into()).collect();
    index.reject_external_collisions(&natives)?;
    if matches!(runtime, Runtime::Host(_)) {
        index.reject_external_collisions(&host_import_profile::runtime_names()?)?;
    }
    Ok(Payload {
        runtime,
        images,
        app,
        bootstrap,
        index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use glue_native::elf::{DynamicSymbol, LoadSegment, VersionRequirement};

    fn base(host: bool) -> Manifest {
        // Construct the exact base resource inventory without opening any input.
        let mut resources: BTreeMap<_, _> = import_profile::app_resources()
            .into_iter()
            .map(|(key, bytes)| {
                let compression = if key == import_profile::CORRUPT_SOURCE {
                    Compression::Stored
                } else {
                    Compression::Deflate
                };
                (
                    key,
                    ResourceSpec {
                        size: bytes.len() as u64,
                        sha256: digest(&bytes),
                        compression,
                    },
                )
            })
            .collect();
        if host {
            let config = host::Config::parse("/host Python imports").unwrap();
            let mut m = profile_manifest(resources, Some(&config)).unwrap();
            m.app_id = "stock-pbs-host-archive-imports".into();
            m.runtimes.get_mut("python").unwrap().build_id =
                "pbs-20261009-cpython-3.13.16-pgo-lto-host-archive-imports-v1".into();
            m
        } else {
            let pins: serde_json::Value =
                serde_json::from_slice(import_profile::SOURCE_PINS).unwrap();
            for (key, value) in pins["files"].as_object().unwrap() {
                resources.insert(
                    format!("stdlib/{key}"),
                    ResourceSpec {
                        size: value["size"].as_u64().unwrap(),
                        sha256: value["sha256"].as_str().unwrap().into(),
                        compression: Compression::Deflate,
                    },
                );
            }
            resources.insert(
                LIBRARY.into(),
                ResourceSpec {
                    size: LIBRARY_SIZE,
                    sha256: LIBRARY_SHA.into(),
                    compression: Compression::Stored,
                },
            );
            resources.insert(
                STDLIB.into(),
                ResourceSpec {
                    size: 100,
                    sha256: digest(b"freeze"),
                    compression: Compression::Stored,
                },
            );
            let mut m = manifest(resources).unwrap();
            m.app_id = "stock-pbs-archive-imports".into();
            let runtime = m.runtimes.get_mut("python").unwrap();
            runtime.build_id = "pbs-20261009-cpython-3.13.16-pgo-lto-archive-imports-v1".into();
            if let Provisioning::Bundled { source, .. } = &mut runtime.provisioning {
                source.variant = "pgo+lto-full/archive-source-imports-v1".into();
            }
            m
        }
    }
    fn specs() -> BTreeMap<String, ResourceSpec> {
        names()
            .into_iter()
            .map(|name| {
                (
                    name,
                    ResourceSpec {
                        size: 1000,
                        sha256: digest(b"fixture image"),
                        compression: Compression::Stored,
                    },
                )
            })
            .collect()
    }
    #[test]
    fn four_provider_cells_preserve_the_exact_base_runtime_and_source_contract() {
        for host in [false, true] {
            for native in [false, true] {
                let base = base(host);
                let m = overlay(&base, &specs(), native.then_some("/native images")).unwrap();
                let decoded = Manifest::from_json(&m.to_json().unwrap()).unwrap();
                let (config, directory) = admit(&decoded).unwrap();
                assert_eq!(
                    crate::profile::validate(&decoded).unwrap().kind,
                    crate::profile::Kind::RegisteredExtensions
                );
                assert_eq!(config.is_some(), host);
                assert_eq!(directory.is_some(), native);
                assert_eq!(base_manifest(&decoded).unwrap().0, base);
                assert_eq!(decoded.runtimes, base.runtimes);
                assert_eq!(decoded.resources.contains_key(LIBRARY), !host);
                assert_eq!(decoded.native_modules.len(), if native { 0 } else { 5 });
                assert_eq!(decoded.host_imports.len(), if native { 5 } else { 0 });
            }
        }
    }
    #[test]
    fn rejects_provider_crosses_unbounded_images_wrong_runtime_and_dependency_edges() {
        let m = overlay(&base(true), &specs(), None).unwrap();
        let mut cases = Vec::new();
        let mut c = m.clone();
        c.native_modules
            .get_mut("glue_native_single.so")
            .unwrap()
            .dependencies
            .clear();
        cases.push(c);
        let mut c = m.clone();
        c.native_modules
            .get_mut("glue_native_multi.so")
            .unwrap()
            .runtime = None;
        cases.push(c);
        let mut c = m.clone();
        c.resources
            .get_mut("native/glue_native_single.so")
            .unwrap()
            .size = IMAGE_LIMIT + 1;
        cases.push(c);
        let mut c = m.clone();
        c.resources.get_mut(APP).unwrap().sha256 = digest(b"otherapp");
        cases.push(c);
        let mut c = m;
        c.host_imports.insert(
            "unexpected".into(),
            HostImportSpec::HostModule {
                target: "linux-arm64".into(),
                path: "/unexpected/image.so".into(),
                runtime: None,
                sha256: Some(digest(b"other")),
            },
        );
        cases.push(c);
        for c in cases {
            assert!(admit(&c).is_err());
        }
        let mut c = overlay(&base(false), &specs(), Some("/native images")).unwrap();
        if let HostImportSpec::HostModule { path, .. } =
            c.host_imports.get_mut("glue_native_multi.so").unwrap()
        {
            *path = "/other/glue_native_multi.so".into();
        }
        assert!(admit(&c).is_err());
    }

    #[test]
    fn rejects_extra_resources_unreachable_images_and_mixed_native_providers() {
        let archived = overlay(&base(true), &specs(), None).unwrap();
        let hosted = overlay(&base(true), &specs(), Some("/native images")).unwrap();
        let mut extra_resource = archived.clone();
        extra_resource
            .resources
            .insert("native/unreachable.so".into(), specs()[DEPENDENCY].clone());
        assert!(admit(&extra_resource).is_err());

        let mut unreachable = archived.clone();
        let mut image = unreachable.native_modules[DEPENDENCY].clone();
        image.resource = "native/unreachable.so".into();
        unreachable
            .resources
            .insert(image.resource.clone(), specs()[DEPENDENCY].clone());
        unreachable
            .native_modules
            .insert("unreachable.so".into(), image);
        assert!(admit(&unreachable).is_err());

        let mut mixed = archived.clone();
        mixed
            .host_imports
            .insert(DEPENDENCY.into(), hosted.host_imports[DEPENDENCY].clone());
        assert!(admit(&mixed).is_err());
        let mut mixed = hosted;
        mixed.native_modules.insert(
            DEPENDENCY.into(),
            archived.native_modules[DEPENDENCY].clone(),
        );
        mixed.resources.insert(
            native_key(DEPENDENCY),
            archived.resources[&native_key(DEPENDENCY)].clone(),
        );
        assert!(admit(&mixed).is_err());
    }

    #[test]
    fn host_image_declarations_require_exact_names_parent_and_explicit_valid_hashes() {
        let original = overlay(&base(true), &specs(), Some("/native images")).unwrap();
        for path in [
            "/another directory/glue_native_single.so",
            "/native images/wrong.so",
            "/native images/../native images/glue_native_single.so",
            "relative/glue_native_single.so",
        ] {
            let mut changed = original.clone();
            if let HostImportSpec::HostModule { path: declared, .. } = changed
                .host_imports
                .get_mut("glue_native_single.so")
                .unwrap()
            {
                *declared = path.into();
            }
            assert!(admit(&changed).is_err(), "accepted {path}");
        }
        for hash in [None, Some("not a SHA-256 digest".into())] {
            let mut changed = original.clone();
            if let HostImportSpec::HostModule { sha256, .. } = changed
                .host_imports
                .get_mut("glue_native_single.so")
                .unwrap()
            {
                *sha256 = hash;
            }
            assert!(admit(&changed).is_err());
        }
        let mut changed = original;
        if let HostImportSpec::HostModule { sha256, .. } = changed
            .host_imports
            .get_mut("glue_native_single.so")
            .unwrap()
        {
            *sha256 = Some(digest(b"a different explicitly selected image"));
        }
        // A declaration selects its image digest. The subsequent bounded file
        // read checks that identity; admission cannot compare unopened content.
        assert!(admit(&changed).is_ok());
    }

    fn function_symbol(name: &str, defined: bool, binding: SymbolBinding) -> DynamicSymbol {
        DynamicSymbol {
            index: 1,
            name: name.into(),
            binding,
            kind: SymbolKind::Function,
            defined,
            value: if defined { 0x800 } else { 0 },
            size: if defined { 16 } else { 0 },
            visibility: 0,
            version_index: if binding == SymbolBinding::Local {
                0
            } else {
                1
            },
            version_hidden: false,
        }
    }

    fn facts(name: &str) -> ElfFacts {
        let dependency = name == DEPENDENCY;
        let export = if dependency {
            DEPENDENCY_EXPORT.into()
        } else {
            format!("PyInit_{}", name.strip_suffix(".so").unwrap())
        };
        ElfFacts {
            soname: name.into(),
            needed: if dependency {
                Vec::new()
            } else {
                vec![DEPENDENCY.into(), "libpython3.13.so.1.0".into()]
            },
            has_constructors: false,
            symbols: vec![function_symbol(&export, true, SymbolBinding::Global)],
            relocations: Vec::new(),
            version_requirements: Vec::new(),
            load_segments: vec![LoadSegment {
                virtual_address: 0x800,
                memory_size: 16,
                file_offset: 0x800,
                file_size: 16,
                flags: 5,
            }],
        }
    }

    #[test]
    fn inspected_facts_reject_local_and_global_python_api_substitutes() {
        let name = "glue_native_multi.so";
        validate_facts(name, &facts(name)).unwrap();
        validate_facts(DEPENDENCY, &facts(DEPENDENCY)).unwrap();
        for api in ["PyLong_FromLong", "PyExc_RuntimeError", "_Py_NoneStruct"] {
            for binding in [SymbolBinding::Local, SymbolBinding::Global] {
                let mut changed = facts(name);
                changed.symbols.push(function_symbol(api, true, binding));
                let error = validate_facts(name, &changed).unwrap_err();
                assert!(error.contains("Python API substitute"), "{error}");
            }
        }
    }

    #[test]
    fn inspected_facts_require_exact_dependency_closure_without_init_or_versions() {
        let name = "glue_native_multi.so";
        for needed in [
            vec![DEPENDENCY.into()],
            vec![DEPENDENCY.into(), "libpython3.14.so.1.0".into()],
            vec![
                DEPENDENCY.into(),
                "libpython3.13.so.1.0".into(),
                DEPENDENCY.into(),
            ],
            vec![
                DEPENDENCY.into(),
                "libpython3.13.so.1.0".into(),
                "other.so".into(),
            ],
        ] {
            let mut changed = facts(name);
            changed.needed = needed;
            assert!(validate_facts(name, &changed).is_err());
        }
        let mut changed = facts(name);
        changed.has_constructors = true;
        assert!(validate_facts(name, &changed).is_err());
        let mut changed = facts(name);
        changed.version_requirements.push(VersionRequirement {
            library: "libpython3.13.so.1.0".into(),
            name: "PYTHON_3.13".into(),
            index: 2,
            flags: 0,
        });
        assert!(validate_facts(name, &changed).is_err());
        let mut changed = facts(DEPENDENCY);
        changed.needed.push("libpython3.13.so.1.0".into());
        assert!(validate_facts(DEPENDENCY, &changed).is_err());
    }

    #[test]
    fn inspected_facts_require_one_exact_global_executable_initializer() {
        let name = "glue_native_multi.so";
        for wrong_name in ["PyInit_glue_native_other", "ordinary_helper"] {
            let mut changed = facts(name);
            changed.symbols[0].name = wrong_name.into();
            assert!(validate_facts(name, &changed).is_err());
        }
        for binding in [SymbolBinding::Local, SymbolBinding::Weak] {
            let mut changed = facts(name);
            changed.symbols[0].binding = binding;
            assert!(validate_facts(name, &changed).is_err());
        }
        let mut changed = facts(name);
        changed.symbols[0].kind = SymbolKind::Object;
        assert!(validate_facts(name, &changed).is_err());
        let mut changed = facts(name);
        changed.symbols[0].value = 0x900;
        assert!(validate_facts(name, &changed).is_err());
        let mut changed = facts(name);
        changed
            .symbols
            .push(function_symbol("extra_export", true, SymbolBinding::Global));
        assert!(validate_facts(name, &changed).is_err());
        for (import, binding) in [
            ("PyLong_FromLong", SymbolBinding::Weak),
            ("unreviewed_runtime_api", SymbolBinding::Global),
        ] {
            let mut changed = facts(name);
            changed
                .symbols
                .push(function_symbol(import, false, binding));
            assert!(validate_facts(name, &changed).is_err());
        }
    }
}
