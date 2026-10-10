//! App-only archive profile using an explicit, independently pinned host stdlib.
#![cfg_attr(
    not(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )),
    allow(dead_code)
)]

use super::*;
use std::io::{Seek, SeekFrom, Write};

const APP_ID: &str = "stock-pbs-host-archive-imports";
const IMPORT_PINS: &[u8] =
    include_bytes!("../../../fixtures/python-host-imports/stdlib-import-pins.json");
const RUNTIME_NAMES: &[u8] =
    include_bytes!("../../../fixtures/python-host-imports/runtime-names.json");

pub(super) fn source_specs() -> Result<BTreeMap<String, ResourceSpec>, String> {
    let selected: serde_json::Value =
        serde_json::from_slice(IMPORT_PINS).map_err(|e| e.to_string())?;
    let all: serde_json::Value =
        serde_json::from_slice(import_profile::SOURCE_PINS).map_err(|e| e.to_string())?;
    if selected["schema_version"] != 0
        || selected["source_inventory_sha256"] != digest(import_profile::SOURCE_PINS)
        || all["artifact_sha256"] != bundle::FULL_SHA256
    {
        return Err("host import source pins differ from the selected PBS inventory".into());
    }
    let files = selected["files"]
        .as_object()
        .ok_or("missing host import source pins")?;
    if files.is_empty() || files.len() > 128 {
        return Err("host import source pin count is outside the bounded profile".into());
    }
    let mut specs = BTreeMap::new();
    for (key, value) in files {
        let spec: ResourceSpec =
            serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        if spec.compression != Compression::Stored
            || all["files"][key]["size"] != spec.size
            || all["files"][key]["sha256"] != spec.sha256
        {
            return Err(format!(
                "host import source identity differs from PBS: {key}"
            ));
        }
        specs.insert(key.clone(), spec);
    }
    Ok(specs)
}

fn runtime_names() -> Result<BTreeSet<String>, String> {
    let builtins: serde_json::Value =
        serde_json::from_slice(RUNTIME_NAMES).map_err(|e| e.to_string())?;
    if builtins["schema_version"] != 0 || builtins["library_sha256"] != LIBRARY_SHA {
        return Err("host runtime module names differ from the selected library".into());
    }
    let mut names = BTreeSet::new();
    for field in ["builtin_names", "bridge_names", "frozen_names"] {
        for name in builtins[field]
            .as_array()
            .ok_or("invalid host runtime module names")?
        {
            names.insert(
                name.as_str()
                    .ok_or("invalid host runtime module name")?
                    .split('.')
                    .next()
                    .unwrap()
                    .into(),
            );
        }
    }
    let pins: serde_json::Value =
        serde_json::from_slice(import_profile::SOURCE_PINS).map_err(|e| e.to_string())?;
    for key in pins["files"]
        .as_object()
        .ok_or("missing stock stdlib source inventory")?
        .keys()
    {
        let first = key.split('/').next().unwrap();
        let name = first.strip_suffix(".py").unwrap_or(first);
        let mut characters = name.bytes();
        if characters
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
            && characters.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            names.insert(name.into());
        }
    }
    Ok(names)
}

fn index(files: BTreeMap<String, Vec<u8>>) -> Result<imports::Index, String> {
    if files.keys().any(|key| !key.starts_with("app/python/")) {
        return Err("host import archive index accepts only app resources".into());
    }
    let index = imports::Index::new(APP_ID, files)?;
    index.reject_external_collisions(&runtime_names()?)?;
    Ok(index)
}

fn specs() -> BTreeMap<String, ResourceSpec> {
    import_profile::app_resources()
        .into_iter()
        .map(|(key, bytes)| {
            let spec = ResourceSpec {
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                compression: if key == import_profile::CORRUPT_SOURCE {
                    Compression::Stored
                } else {
                    Compression::Deflate
                },
            };
            (key, spec)
        })
        .collect()
}

fn manifest_for(
    resources: BTreeMap<String, ResourceSpec>,
    config: &host::Config,
) -> Result<Manifest, String> {
    let mut manifest = profile_manifest(resources, Some(config))?;
    manifest.app_id = APP_ID.into();
    manifest.runtimes.get_mut("python").unwrap().build_id =
        "pbs-20261009-cpython-3.13.16-pgo-lto-host-archive-imports-v1".into();
    manifest.validate().map_err(|e| e.to_string())?;
    Ok(manifest)
}

fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_archive_bytes: 128 * 1024,
        max_manifest_bytes: 16 * 1024,
        max_entry_bytes: 64 * 1024,
        max_total_uncompressed_bytes: 128 * 1024,
        max_entries: 32,
        max_central_directory_bytes: 16 * 1024,
        ..ArchiveLimits::default()
    }
}

fn admit(manifest: &Manifest) -> Result<host::Config, String> {
    let runtime = manifest
        .runtimes
        .get("python")
        .ok_or("missing host Python runtime")?;
    let Provisioning::Host {
        runtime_library,
        stdlib,
        discovery: HostDiscovery::ExplicitPaths,
    } = &runtime.provisioning
    else {
        return Err("archive differs from the host archive imports profile".into());
    };
    let prefix = stdlib
        .strip_suffix("/lib/python3.13")
        .ok_or("host import stdlib does not use the fixed installation layout")?;
    let config = host::Config::parse(prefix)?;
    if runtime_library != &config.library
        || stdlib != &config.stdlib
        || *manifest != manifest_for(specs(), &config)?
    {
        return Err("archive differs from the host archive imports profile".into());
    }
    Ok(config)
}

pub(super) fn prepare(full: &Path, prefix: &str, output: &Path) -> Result<(), String> {
    let config = host::Config::parse(prefix)?;
    let pins = glue_pbs::pins::Pins::from_json(PINS)?;
    let inspection = glue_pbs::inspect(
        &pins,
        &mut File::open(full).map_err(|e| e.to_string())?,
        None,
    )?;
    // The inspector verifies the complete pinned full input. Independently tie
    // this profile's supplemental identities to its actual regular members.
    for (key, spec) in source_specs()? {
        let member = inspection
            .full
            .entries
            .get(&format!("python/install/lib/python3.13/{key}"))
            .ok_or_else(|| format!("missing host import source in PBS: {key}"))?;
        if member.kind != glue_pbs::archive::EntryKind::RegularFile
            || member.size != spec.size
            || member.sha256.as_deref() != Some(spec.sha256.as_str())
        {
            return Err(format!(
                "host import source differs from inspected PBS: {key}"
            ));
        }
    }
    let resources = import_profile::app_resources();
    index(
        resources
            .iter()
            .filter(|(key, _)| key.starts_with("app/python/"))
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect(),
    )?;
    let manifest = manifest_for(specs(), &config)?;
    admit(&manifest)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    write_archive(file, &manifest, &resources).map_err(|e| e.to_string())?;
    println!("prepared explicit host Python archive source/resource fixture");
    Ok(())
}

pub(super) struct Payload {
    pub config: host::Config,
    pub app: Vec<u8>,
    pub bootstrap: Vec<u8>,
    pub index: imports::Index,
}

pub(super) fn read(path: &Path) -> Result<Payload, String> {
    let mut archive =
        Archive::open_with_limits(File::open(path).map_err(|e| e.to_string())?, limits())
            .map_err(|e| e.to_string())?;
    let config = admit(archive.manifest())?;
    let keys: Vec<_> = archive.manifest().resources.keys().cloned().collect();
    let mut files = BTreeMap::new();
    for key in keys {
        files.insert(
            key.clone(),
            archive.read_resource(&key).map_err(|e| e.to_string())?,
        );
    }
    let app = files.remove(APP).ok_or("missing host archive app")?;
    let bootstrap = files
        .remove(import_profile::IMPORTER)
        .ok_or("missing shared importer bootstrap")?;
    Ok(Payload {
        config,
        app,
        bootstrap,
        index: index(files)?,
    })
}

pub(super) fn corrupt(input: &Path, output: &Path) -> Result<(), String> {
    let bytes = bounded_file(input, limits().max_archive_bytes)?;
    let archive = Archive::open_with_limits(std::io::Cursor::new(&bytes), limits())
        .map_err(|e| e.to_string())?;
    admit(archive.manifest())?;
    let entry = &archive.entries()[import_profile::CORRUPT_SOURCE];
    if entry.compression != Compression::Stored || entry.size == 0 {
        return Err("invalid host source corruption fixture".into());
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
    println!("prepared host archive source CRC rejection control");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_archive_contains_only_exact_shared_app_and_importer() {
        let config = host::Config::parse("/host Python imports").unwrap();
        let m = manifest_for(specs(), &config).unwrap();
        assert_eq!(admit(&m).unwrap(), config);
        assert_eq!(m.resources.len(), 18);
        assert!(!m.resources.contains_key(LIBRARY));
        assert!(!m.resources.contains_key(STDLIB));
        assert_eq!(
            m.resources[APP].sha256,
            digest(&import_profile::app_resources()[APP])
        );
        assert_eq!(source_specs().unwrap().len(), 63);
        index(
            import_profile::app_resources()
                .into_iter()
                .filter(|(key, _)| key.starts_with("app/python/"))
                .collect(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_provider_identity_inventory_and_path_drift() {
        let config = host::Config::parse("/host Python imports").unwrap();
        let good = manifest_for(specs(), &config).unwrap();
        let mut bundled_resources = good.resources.clone();
        for key in [LIBRARY, STDLIB] {
            bundled_resources.insert(key.into(), good.resources[APP].clone());
        }
        let bundled = manifest(bundled_resources).unwrap();
        for which in 0..7 {
            let mut bad = good.clone();
            match which {
                0 => bad.app_id.push('x'),
                1 => bad.runtimes.get_mut("python").unwrap().build_id.push('x'),
                2 => bad.resources.get_mut(APP).unwrap().sha256 = "0".repeat(64),
                3 => {
                    bad.resources
                        .get_mut(import_profile::CORRUPT_SOURCE)
                        .unwrap()
                        .compression = Compression::Deflate
                }
                4 => {
                    bad.resources
                        .insert("stdlib/json.py".into(), good.resources[APP].clone());
                }
                5 => {
                    if let Provisioning::Host {
                        runtime_library, ..
                    } = &mut bad.runtimes.get_mut("python").unwrap().provisioning
                    {
                        runtime_library.push('x');
                    }
                }
                _ => {
                    bad.runtimes.get_mut("python").unwrap().provisioning =
                        bundled.runtimes["python"].provisioning.clone()
                }
            }
            assert!(admit(&bad).is_err(), "mutation {which}");
        }
    }

    #[test]
    fn rejects_runtime_stdlib_bridge_shadows_and_extra_archive_roots() {
        for name in [
            "json",
            "importlib",
            "math",
            "sys",
            "os",
            "_glue_archive",
            "_frozen_importlib",
            "__main__",
            "__hello_alias__",
            "__phello_alias__",
            "__hello_only__",
        ] {
            let files = BTreeMap::from([(format!("app/python/{name}.py"), Vec::new())]);
            assert!(index(files).is_err(), "shadow {name}");
        }
        assert!(index(BTreeMap::from([("stdlib/json.py".into(), Vec::new())])).is_err());
    }
}
