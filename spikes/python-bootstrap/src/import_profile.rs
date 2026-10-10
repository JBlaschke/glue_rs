//! Exact pinned source/resource fixture profile, separate from product acquisition.
use super::*;
use std::io::{Seek, SeekFrom, Write};

pub(super) const IMPORTER: &str = "python/archive-importer.py";
const BOOTSTRAP: &[u8] = include_bytes!("../../../fixtures/python-imports/bootstrap.py");
pub(super) const SOURCE_PINS: &[u8] =
    include_bytes!("../../../fixtures/python-imports/stdlib-pins.json");
pub(super) const CORRUPT_SOURCE: &str = "app/python/glue_demo/__init__.py";
const SOURCE_PREFIX: &str = "python/install/lib/python3.13/";
const APP_ID: &str = "stock-pbs-archive-imports";

fn fixture_files() -> BTreeMap<String, Vec<u8>> {
    macro_rules! file {
        ($key:literal) => {
            (
                $key,
                include_bytes!(concat!("../../../fixtures/python-imports/input/", $key)).as_slice(),
            )
        };
    }
    [
        file!("app/main.py"),
        file!("app/python/glue_demo/__init__.py"),
        file!("app/python/glue_demo/answer.py"),
        file!("app/python/glue_demo/broken.py"),
        file!("app/python/glue_demo/bytecode_only.pyc"),
        file!("app/python/glue_demo/cycle_a.py"),
        file!("app/python/glue_demo/cycle_b.py"),
        file!("app/python/glue_demo/data/binary.bin"),
        file!("app/python/glue_demo/data/text.txt"),
        file!("app/python/glue_demo/dependency.py"),
        file!("app/python/glue_demo/encoded.py"),
        file!("app/python/glue_demo/nested/__init__.py"),
        file!("app/python/glue_demo/nested/value.py"),
        file!("app/python/glue_demo/syntax_error.py"),
        file!("app/python/glue_ns/data/info.txt"),
        file!("app/python/glue_ns/part.py"),
        file!("app/python/standalone.py"),
    ]
    .into_iter()
    .map(|(key, bytes)| (key.into(), bytes.to_vec()))
    .collect()
}

pub(super) fn app_resources() -> BTreeMap<String, Vec<u8>> {
    let mut resources = fixture_files();
    resources.insert(IMPORTER.into(), BOOTSTRAP.to_vec());
    resources
}

fn source_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let pins: serde_json::Value = serde_json::from_slice(SOURCE_PINS).map_err(|e| e.to_string())?;
    if pins["schema_version"] != 0 || pins["artifact_sha256"] != bundle::FULL_SHA256 {
        return Err("stdlib source inventory pin differs from selected PBS input".into());
    }
    let mut specs = BTreeMap::new();
    let files = pins["files"]
        .as_object()
        .ok_or("invalid checked-in source inventory")?;
    if files.len() != 2174 {
        return Err("stdlib source inventory count differs from pin".into());
    }
    for (key, value) in files {
        let path = format!("stdlib/{key}");
        ResourcePath::new(&path).map_err(|e| e.to_string())?;
        let size = value["size"].as_u64().ok_or("missing source size")?;
        if size > imports::MAX_REPLY as u64 {
            return Err("stdlib source exceeds callback bound".into());
        }
        specs.insert(
            path,
            ResourceSpec {
                size,
                sha256: value["sha256"]
                    .as_str()
                    .ok_or("missing source hash")?
                    .into(),
                compression: Compression::Deflate,
            },
        );
    }
    Ok(specs)
}

fn fixed_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let mut specs = source_specs()?;
    for (key, bytes) in app_resources() {
        specs.insert(
            key.clone(),
            ResourceSpec {
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                compression: if key == CORRUPT_SOURCE {
                    Compression::Stored
                } else {
                    Compression::Deflate
                },
            },
        );
    }
    specs.insert(
        LIBRARY.into(),
        ResourceSpec {
            size: LIBRARY_SIZE,
            sha256: LIBRARY_SHA.into(),
            compression: Compression::Stored,
        },
    );
    Ok(specs)
}

fn manifest_for(resources: BTreeMap<String, ResourceSpec>) -> Result<Manifest, String> {
    let mut m = manifest(resources)?;
    m.app_id = APP_ID.into();
    let runtime = m.runtimes.get_mut("python").unwrap();
    runtime.build_id = "pbs-20261009-cpython-3.13.16-pgo-lto-archive-imports-v1".into();
    if let Provisioning::Bundled { source, .. } = &mut runtime.provisioning {
        source.variant = "pgo+lto-full/archive-source-imports-v1".into();
    }
    m.validate().map_err(|e| e.to_string())?;
    Ok(m)
}

fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_manifest_bytes: 2 * 1024 * 1024,
        max_archive_bytes: 128 * 1024 * 1024,
        max_entry_bytes: 80 * 1024 * 1024,
        max_total_uncompressed_bytes: 128 * 1024 * 1024,
        max_entries: 4096,
        max_central_directory_bytes: 2 * 1024 * 1024,
        ..ArchiveLimits::default()
    }
}

pub(super) fn prepare(full: &Path, bundle_path: &Path, output: &Path) -> Result<(), String> {
    let mut resources = fixture_files();
    let bundle_bytes = bounded_file(bundle_path, BUNDLE_LIMIT)?;
    let bundle = Bundle::parse(&bundle_bytes)?;
    let sources = source_specs()?;
    let mut selection: BTreeSet<_> = sources
        .keys()
        .map(|k| format!("{SOURCE_PREFIX}{}", k.strip_prefix("stdlib/").unwrap()))
        .collect();
    selection.insert(LIBRARY_MEMBER.into());
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let selected = glue_pbs::inspect_full_selected(
        &pins,
        &mut File::open(full).map_err(|e| e.to_string())?,
        &selection,
        128 * 1024 * 1024,
    )?;
    bundle.validate_sources(&selected.inspection)?;
    let projected: BTreeSet<_> = selected
        .inspection
        .full
        .entries
        .iter()
        .filter(|(k, e)| {
            k.starts_with(SOURCE_PREFIX)
                && k.ends_with(".py")
                && e.kind == glue_pbs::archive::EntryKind::RegularFile
        })
        .map(|(k, _)| k.clone())
        .collect();
    let expected: BTreeSet<_> = selection
        .iter()
        .filter(|k| *k != LIBRARY_MEMBER)
        .cloned()
        .collect();
    if projected != expected {
        return Err("full PBS source projection differs from checked-in inventory".into());
    }
    for (key, bytes) in selected.files {
        if key == LIBRARY_MEMBER {
            check_library(&bytes)?;
            resources.insert(LIBRARY.into(), bytes);
        } else {
            let resource = format!(
                "stdlib/{}",
                key.strip_prefix(SOURCE_PREFIX)
                    .ok_or("unexpected selected member")?
            );
            let spec = &sources[&resource];
            if bytes.len() as u64 != spec.size || digest(&bytes) != spec.sha256 {
                return Err(format!(
                    "pinned stdlib source identity mismatch: {resource}"
                ));
            }
            resources.insert(resource, bytes);
        }
    }
    resources.insert(STDLIB.into(), bundle_bytes);
    resources.insert(IMPORTER.into(), BOOTSTRAP.to_vec());
    let specs = resources
        .iter()
        .map(|(key, bytes)| {
            (
                key.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression: if key == LIBRARY || key == STDLIB || key == CORRUPT_SOURCE {
                        Compression::Stored
                    } else {
                        Compression::Deflate
                    },
                },
            )
        })
        .collect();
    let m = manifest_for(specs)?;
    admit(&m)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &m, &resources).map_err(|e| e.to_string())?;
    println!("prepared stock PBS archive source/resource fixture");
    Ok(())
}

fn admit(m: &Manifest) -> Result<(), String> {
    if *m != manifest_for(m.resources.clone())? {
        return Err("archive differs from the archive Python imports profile".into());
    }
    let mut expected = fixed_specs()?;
    let frozen = m
        .resources
        .get(STDLIB)
        .ok_or("missing frozen startup bundle")?;
    if frozen.size > BUNDLE_LIMIT || frozen.compression != Compression::Stored {
        return Err("invalid frozen startup resource bound/compression".into());
    }
    expected.insert(STDLIB.into(), frozen.clone());
    if m.resources != expected {
        return Err("archive import resource inventory/identities differ from fixture pins".into());
    }
    Ok(())
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )),
    allow(dead_code)
)]
pub(super) struct Payload {
    pub library: Vec<u8>,
    pub bundle: Bundle,
    pub app: Vec<u8>,
    pub bootstrap: Vec<u8>,
    pub index: imports::Index,
}

#[cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )),
    allow(dead_code)
)]
pub(super) fn read(path: &Path) -> Result<Payload, String> {
    let mut archive =
        Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, limits())
            .map_err(|e| e.to_string())?;
    admit(archive.manifest())?;
    let library = archive.read_resource(LIBRARY).map_err(|e| e.to_string())?;
    check_library(&library)?;
    let bundle = Bundle::parse(&archive.read_resource(STDLIB).map_err(|e| e.to_string())?)?;
    let app = archive.read_resource(APP).map_err(|e| e.to_string())?;
    let bootstrap = archive.read_resource(IMPORTER).map_err(|e| e.to_string())?;
    let keys: Vec<_> = archive
        .manifest()
        .resources
        .keys()
        .filter(|k| k.starts_with("stdlib/") || k.starts_with("app/python/"))
        .cloned()
        .collect();
    let mut files = BTreeMap::new();
    for key in keys {
        files.insert(
            key.clone(),
            archive.read_resource(&key).map_err(|e| e.to_string())?,
        );
    }
    let index = imports::Index::new(APP_ID, files)?;
    Ok(Payload {
        library,
        bundle,
        app,
        bootstrap,
        index,
    })
}

pub(super) fn corrupt(input: &Path, output: &Path) -> Result<(), String> {
    let bytes = bounded_file(input, limits().max_archive_bytes)?;
    let archive = Archive::open_with_limits(std::io::Cursor::new(&bytes), limits())
        .map_err(|e| e.to_string())?;
    admit(archive.manifest())?;
    let entry = &archive.entries()[CORRUPT_SOURCE];
    if entry.compression != Compression::Stored || entry.size == 0 {
        return Err("invalid source corruption fixture".into());
    }
    let manifest_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let offset = 64u64
        .checked_add(manifest_len)
        .and_then(|v| v.checked_add(entry.data_offset))
        .ok_or("source offset overflow")?;
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
    println!("prepared corrupt stored source control");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Manifest {
        let mut specs = fixed_specs().unwrap();
        specs.insert(
            STDLIB.into(),
            ResourceSpec {
                size: 1,
                sha256: digest(b"x"),
                compression: Compression::Stored,
            },
        );
        manifest_for(specs).unwrap()
    }
    #[test]
    fn exact_source_inventory_and_profile_admission() {
        let specs = source_specs().unwrap();
        assert_eq!(specs.values().map(|s| s.size).sum::<u64>(), 39_158_056);
        let m = profile();
        admit(&m).unwrap();
        assert!(admit_manifest(&m).is_err());
        assert!(admit_host_manifest(&m).is_err());
        let mut files: BTreeMap<_, _> = specs.keys().map(|key| (key.clone(), Vec::new())).collect();
        files.extend(
            fixture_files()
                .into_iter()
                .filter(|(key, _)| key.starts_with("app/python/")),
        );
        imports::Index::new(APP_ID, files).unwrap();
    }
    #[test]
    fn rejects_source_hash_compression_and_provider_drift() {
        let m = profile();
        for key in [
            CORRUPT_SOURCE,
            "stdlib/importlib/resources/_common.py",
            LIBRARY,
        ] {
            let mut changed = m.clone();
            changed.resources.get_mut(key).unwrap().sha256 = digest(b"changed");
            assert!(admit(&changed).is_err());
        }
        let mut changed = m.clone();
        changed
            .resources
            .get_mut(CORRUPT_SOURCE)
            .unwrap()
            .compression = Compression::Deflate;
        assert!(admit(&changed).is_err());
        let mut changed = m;
        changed.runtimes.get_mut("python").unwrap().build_id = "another-build".into();
        assert!(admit(&changed).is_err());
    }
    #[test]
    fn rejects_missing_extra_and_oversized_resources() {
        let m = profile();
        let mut changed = m.clone();
        changed.resources.remove("stdlib/tempfile.py");
        assert!(admit(&changed).is_err());
        let mut changed = m.clone();
        changed.resources.insert(
            "app/python/extra.py".into(),
            ResourceSpec {
                size: 0,
                sha256: digest(b""),
                compression: Compression::Stored,
            },
        );
        assert!(admit(&changed).is_err());
        let mut changed = m;
        changed.resources.get_mut(STDLIB).unwrap().size = BUNDLE_LIMIT + 1;
        assert!(admit(&changed).is_err());
    }
}
