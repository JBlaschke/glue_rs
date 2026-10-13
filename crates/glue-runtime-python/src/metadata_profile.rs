//! Bounded distribution metadata for the pinned source-application profiles.
//!
//! Metadata is archive data, never a reason to search installed site-packages.
//! Both declaration and content checks finish before acquiring any provider.
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
use sha2::{Digest, Sha256};

pub(super) const HELPER: &str = "python/archive-metadata.py";
pub(super) const BOOTSTRAP: &[u8] =
    include_bytes!("../../../fixtures/python-metadata/bootstrap.py");
pub(super) const BUNDLED_BUILD_ID: &str =
    "pbs-20261009-cpython-3.13.16-pgo-lto-bundled-metadata-apps-v1";
pub(super) const HOST_BUILD_ID: &str = "pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1";
pub(super) const INSTALL_BUILD_ID: &str =
    "pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1";
const VARIANT: &str = "pgo+lto-full/bundled-metadata-apps-v1";
const ROOT: &str = "app/python/";
const MAX_DISTRIBUTIONS: usize = 64;
const MAX_METADATA: u64 = 64 * 1024;
const MAX_RECORD: u64 = 256 * 1024;
const MAX_ROWS: usize = 1024;

pub(super) fn limits_bundled() -> ArchiveLimits {
    source_app_profile::limits()
}

pub(super) fn limits_host() -> ArchiveLimits {
    host_source_app_profile::limits()
}

fn helper_spec() -> ResourceSpec {
    ResourceSpec {
        size: BOOTSTRAP.len() as u64,
        sha256: digest(BOOTSTRAP),
        compression: Compression::Deflate,
    }
}

/// Collect only top-level .dist-info directories and bound their declarations.
fn directories<'a>(
    files: impl Iterator<Item = (&'a String, u64)>,
) -> Result<BTreeSet<String>, String> {
    let files: BTreeMap<_, _> = files.map(|(key, size)| (key.as_str(), size)).collect();
    let mut directories = BTreeSet::new();
    for (key, size) in &files {
        let Some(relative) = key.strip_prefix(ROOT) else {
            continue;
        };
        let parts: Vec<_> = relative.split('/').collect();
        if !parts.iter().any(|part| part.ends_with(".dist-info")) {
            continue;
        }
        if parts.len() < 2
            || !parts[0].ends_with(".dist-info")
            || parts[1..].iter().any(|part| part.ends_with(".dist-info"))
        {
            return Err(format!(
                "distribution metadata must be a top-level directory: {key}"
            ));
        }
        folder_identity(parts[0])?;
        directories.insert(parts[0].to_owned());
        if directories.len() > MAX_DISTRIBUTIONS {
            return Err("archive distribution count exceeds 64".into());
        }
        let bound = match parts[1..].join("/").as_str() {
            "METADATA" | "top_level.txt" | "entry_points.txt" => MAX_METADATA,
            "RECORD" => MAX_RECORD,
            _ => continue,
        };
        if *size > bound {
            return Err(format!("distribution metadata exceeds its bound: {key}"));
        }
    }
    for directory in &directories {
        for member in ["METADATA", "RECORD"] {
            if !files.contains_key(format!("{ROOT}{directory}/{member}").as_str()) {
                return Err(format!("distribution {directory} is missing {member}"));
            }
        }
    }
    Ok(directories)
}

fn normalized_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("distribution Name requires 1..128 ASCII project-name characters with alphanumeric endpoints".into());
    }
    let mut result = String::new();
    let mut separator = false;
    for byte in name.bytes() {
        if b"._-".contains(&byte) {
            if !separator {
                result.push('-');
            }
            separator = true;
        } else {
            result.push(char::from(byte.to_ascii_lowercase()));
            separator = false;
        }
    }
    Ok(result)
}

fn version(version: &str) -> Result<(), String> {
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+!-".contains(&byte))
    {
        return Err("distribution Version requires 1..128 ASCII version characters".into());
    }
    Ok(())
}

fn folder_identity(directory: &str) -> Result<(String, &str), String> {
    let stem = directory
        .strip_suffix(".dist-info")
        .ok_or("distribution directory is missing .dist-info suffix")?;
    let (name, release) = stem
        .rsplit_once('-')
        .ok_or("distribution directory requires name-version.dist-info")?;
    version(release)?;
    Ok((normalized_name(name)?, release))
}

fn declaration(manifest: &Manifest, build_id: &str, old_id: &str) -> Result<Manifest, String> {
    manifest.validate().map_err(|error| error.to_string())?;
    let limit = if build_id == BUNDLED_BUILD_ID {
        limits_bundled().max_manifest_bytes
    } else {
        limits_host().max_manifest_bytes
    };
    if manifest.to_json().map_err(|error| error.to_string())?.len() as u64 > limit {
        return Err(format!(
            "original distribution metadata manifest exceeds {limit} bytes"
        ));
    }
    if manifest.resources.get(HELPER) != Some(&helper_spec()) {
        return Err(
            "distribution metadata helper identity or compression differs from fixed pin".into(),
        );
    }
    directories(
        manifest
            .resources
            .iter()
            .map(|(key, spec)| (key, spec.size)),
    )?;
    let mut old = manifest.clone();
    old.resources.remove(HELPER);
    let runtime = old
        .runtimes
        .get_mut("python")
        .ok_or("distribution metadata requires the pinned Python runtime identity")?;
    if runtime.build_id != build_id {
        return Err("distribution metadata runtime build identity differs from fixed pin".into());
    }
    runtime.build_id = old_id.into();
    Ok(old)
}

pub(super) fn admit_bundled(manifest: &Manifest) -> Result<(), String> {
    let mut old = declaration(manifest, BUNDLED_BUILD_ID, source_app_profile::BUILD_ID)?;
    let Provisioning::Bundled { source, .. } =
        &mut old.runtimes.get_mut("python").unwrap().provisioning
    else {
        return Err("distribution metadata requires the pinned bundled provider".into());
    };
    if source.variant != VARIANT {
        return Err("distribution metadata bundled source variant differs from fixed pin".into());
    }
    source.variant = source_app_profile::VARIANT.into();
    source_app_profile::admit(&old)
}

pub(super) fn admit_host(manifest: &Manifest) -> Result<host::Config, String> {
    host_source_app_profile::admit(&declaration(
        manifest,
        HOST_BUILD_ID,
        host_source_app_profile::BUILD_ID,
    )?)
}

pub(super) fn admit_install_host(manifest: &Manifest) -> Result<host::Config, String> {
    install_host_source_app_profile::admit(&declaration(
        manifest,
        INSTALL_BUILD_ID,
        install_host_source_app_profile::BUILD_ID,
    )?)
}

pub(super) fn read_bundled(archive: Archive<File>) -> Result<import_profile::Payload, String> {
    source_app_profile::read_archive_with(archive, admit_bundled, prepare)
}

pub(super) fn read_host(
    archive: Archive<File>,
) -> Result<host_source_app_profile::Payload, String> {
    host_source_app_profile::read_archive_prepared(archive, admit_host, prepare)
}

pub(super) fn read_install_host(
    archive: Archive<File>,
) -> Result<host_source_app_profile::Payload, String> {
    host_source_app_profile::read_archive_prepared(archive, admit_install_host, prepare)
}

fn prepare(files: &mut BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    verify_contents(files)?;
    let helper = files
        .remove(HELPER)
        .ok_or("distribution metadata helper bytes are missing")?;
    if helper != BOOTSTRAP {
        return Err("distribution metadata helper bytes differ from fixed pin".into());
    }
    Ok(helper)
}

fn text<'a>(files: &'a BTreeMap<String, Vec<u8>>, key: &str) -> Result<&'a str, String> {
    std::str::from_utf8(
        files
            .get(key)
            .ok_or_else(|| format!("missing metadata file: {key}"))?,
    )
    .map_err(|_| format!("distribution metadata is not UTF-8: {key}"))
}

fn metadata_identity(metadata: &str) -> Result<(String, String), String> {
    let mut name = None;
    let mut release = None;
    let mut previous_identity = false;
    let mut saw_header = false;
    for raw in metadata.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.contains('\r') {
            return Err("distribution METADATA contains a malformed header line ending".into());
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if previous_identity || !saw_header {
                return Err(
                    "distribution METADATA has a folded identity header or orphan continuation"
                        .into(),
                );
            }
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or("distribution METADATA contains a malformed header")?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| (33..=126).contains(&byte) && byte != b':')
        {
            return Err("distribution METADATA contains an invalid header name".into());
        }
        let value = value.trim_matches([' ', '\t']);
        previous_identity = key.eq_ignore_ascii_case("Name") || key.eq_ignore_ascii_case("Version");
        saw_header = true;
        if key.eq_ignore_ascii_case("Name") {
            if name.replace(normalized_name(value)?).is_some() {
                return Err("distribution METADATA has duplicate Name headers".into());
            }
        } else if key.eq_ignore_ascii_case("Version") {
            version(value)?;
            if release.replace(value.to_owned()).is_some() {
                return Err("distribution METADATA has duplicate Version headers".into());
            }
        }
    }
    Ok((
        name.ok_or("distribution METADATA is missing Name")?,
        release.ok_or("distribution METADATA is missing Version")?,
    ))
}

/// Strict CSV keeps quoted commas and doubled quotes without treating malformed
/// quoting, blank rows or extra columns as a different record interpretation.
fn record_rows(record: &str) -> Result<Vec<[String; 3]>, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Start,
        Plain,
        Quoted,
        Closed,
    }
    let mut chars = record.chars().peekable();
    let mut state = State::Start;
    let mut field = String::new();
    let mut row = Vec::new();
    let mut rows = Vec::new();
    while let Some(ch) = chars.next() {
        if state == State::Quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    state = State::Closed;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        if ch == ',' || ch == '\n' || ch == '\r' {
            row.push(std::mem::take(&mut field));
            if ch == ',' {
                if row.len() >= 3 {
                    return Err("distribution RECORD requires exactly three CSV columns".into());
                }
            } else {
                if ch == '\r' && chars.next() != Some('\n') {
                    return Err("distribution RECORD has a malformed line ending".into());
                }
                finish_row(&mut rows, std::mem::take(&mut row))?;
            }
            state = State::Start;
        } else if ch == '"' && state == State::Start {
            state = State::Quoted;
        } else if ch == '"' || state == State::Closed {
            return Err("distribution RECORD contains malformed CSV quoting".into());
        } else {
            field.push(ch);
            state = State::Plain;
        }
    }
    if state == State::Quoted {
        return Err("distribution RECORD contains an unterminated CSV quote".into());
    }
    if state != State::Start || !row.is_empty() {
        row.push(field);
        finish_row(&mut rows, row)?;
    }
    Ok(rows)
}

fn finish_row(rows: &mut Vec<[String; 3]>, row: Vec<String>) -> Result<(), String> {
    rows.push(
        row.try_into()
            .map_err(|_| "distribution RECORD requires exactly three CSV columns")?,
    );
    if rows.len() > MAX_ROWS {
        return Err("distribution RECORD exceeds 1024 rows".into());
    }
    Ok(())
}

fn record_hash(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(43);
    for group in digest.chunks(3) {
        encoded.push(char::from(ALPHABET[(group[0] >> 2) as usize]));
        encoded.push(char::from(
            ALPHABET[(((group[0] & 3) << 4) | (group.get(1).copied().unwrap_or(0) >> 4)) as usize],
        ));
        if group.len() > 1 {
            encoded.push(char::from(
                ALPHABET
                    [(((group[1] & 15) << 2) | (group.get(2).copied().unwrap_or(0) >> 6)) as usize],
            ));
        }
        if group.len() > 2 {
            encoded.push(char::from(ALPHABET[(group[2] & 63) as usize]));
        }
    }
    format!("sha256={encoded}")
}

fn verify_contents(files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let directories = directories(files.iter().map(|(key, bytes)| (key, bytes.len() as u64)))?;
    let mut names = BTreeSet::new();
    let mut owned = BTreeSet::new();
    for directory in directories {
        let prefix = format!("{ROOT}{directory}/");
        let metadata_key = format!("{prefix}METADATA");
        let (name, release) = metadata_identity(text(files, &metadata_key)?)?;
        let (folder_name, folder_release) = folder_identity(&directory)?;
        if name != folder_name || release != folder_release {
            return Err(format!(
                "distribution {directory} Name or Version differs from its directory"
            ));
        }
        if !names.insert(name) {
            return Err("archive distributions have duplicate normalized Names".into());
        }
        for member in ["top_level.txt", "entry_points.txt"] {
            let key = format!("{prefix}{member}");
            if files.contains_key(&key) {
                text(files, &key)?;
            }
        }
        let record_key = format!("{prefix}RECORD");
        let mut recorded = BTreeSet::new();
        for [path, hash, size] in record_rows(text(files, &record_key)?)? {
            ResourcePath::new(&path).map_err(|error| format!("invalid RECORD path: {error}"))?;
            if path.contains(['\r', '\n']) {
                return Err("distribution RECORD paths cannot contain CR or LF".into());
            }
            let first = path.split('/').next().unwrap();
            if first.ends_with(".dist-info") && first != directory {
                return Err(
                    "distribution RECORD references another distribution's metadata".into(),
                );
            }
            let key = format!("{ROOT}{path}");
            let bytes = files
                .get(&key)
                .ok_or_else(|| format!("distribution RECORD references a missing file: {path}"))?;
            if !recorded.insert(key.clone()) {
                return Err("distribution RECORD contains duplicate paths".into());
            }
            if !owned.insert(key.clone()) {
                return Err("archive distributions claim the same RECORD file".into());
            }
            if key == record_key {
                if !hash.is_empty() || !size.is_empty() {
                    return Err(
                        "distribution RECORD self-entry requires empty hash and size".into(),
                    );
                }
                continue;
            }
            if !hash.is_empty() && hash != record_hash(bytes) {
                return Err(format!("distribution RECORD SHA-256 differs for {path}"));
            }
            if !size.is_empty()
                && (!size.bytes().all(|byte| byte.is_ascii_digit())
                    || size.parse::<u64>().ok() != Some(bytes.len() as u64))
            {
                return Err(format!("distribution RECORD size differs for {path}"));
            }
        }
        for key in files.keys().filter(|key| key.starts_with(&prefix)) {
            if !recorded.contains(key) {
                return Err(format!(
                    "distribution RECORD is missing metadata member: {key}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const DIRECTORY: &str = "Customer_Demo-1.2.dist-info";
    const METADATA: &str = "app/python/Customer_Demo-1.2.dist-info/METADATA";
    const RECORD: &str = "app/python/Customer_Demo-1.2.dist-info/RECORD";

    fn spec(bytes: &[u8]) -> ResourceSpec {
        ResourceSpec {
            size: bytes.len() as u64,
            sha256: digest(bytes),
            compression: Compression::Stored,
        }
    }

    fn contents() -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::from([
            (HELPER.into(), BOOTSTRAP.to_vec()),
            (import_profile::IMPORTER.into(), import_profile::BOOTSTRAP.to_vec()),
            ("app/main.py".into(), b"import customer\n".to_vec()),
            ("app/python/customer/__init__.py".into(), b"answer = 42\n".to_vec()),
            ("app/python/customer/data,quoted.txt".into(), b"data\n".to_vec()),
            (METADATA.into(), b"Metadata-Version: 2.3\r\nName: Customer.Demo\r\nVersion: 1.2\r\nSummary: A package\r\n with a continued summary\r\n\r\nDescription with UTF-8: caf\xc3\xa9\n".to_vec()),
            (format!("{ROOT}{DIRECTORY}/top_level.txt"), b"customer\n".to_vec()),
            (format!("{ROOT}{DIRECTORY}/entry_points.txt"), b"[console_scripts]\nreport = customer:run\n".to_vec()),
        ]);
        let mut record = String::new();
        for (key, bytes) in &files {
            if let Some(relative) = key.strip_prefix(ROOT) {
                let quoted = relative.replace('"', "\"\"");
                record.push_str(&format!(
                    "\"{quoted}\",{},{}\r\n",
                    record_hash(bytes),
                    bytes.len()
                ));
            }
        }
        record.push_str(&format!("{DIRECTORY}/RECORD,,\r\n"));
        files.insert(RECORD.into(), record.into_bytes());
        files
    }

    fn host_manifest(files: &BTreeMap<String, Vec<u8>>, install: bool) -> Manifest {
        let mut resources: BTreeMap<_, _> = files
            .iter()
            .map(|(key, bytes)| (key.clone(), spec(bytes)))
            .collect();
        resources.extend(host_source_app_profile::fixed_specs());
        resources.insert(HELPER.into(), helper_spec());
        host_source_app_profile::manifest_for_build(
            "customer.report",
            "report",
            APP,
            resources,
            &host::Config::parse("/missing Python metadata provider").unwrap(),
            if install {
                INSTALL_BUILD_ID
            } else {
                HOST_BUILD_ID
            },
        )
        .unwrap()
    }

    fn bundled_manifest(files: &BTreeMap<String, Vec<u8>>) -> Manifest {
        let mut resources = source_app_profile::fixed_specs().unwrap();
        resources.extend(
            files
                .iter()
                .filter(|(key, _)| key.starts_with("app/"))
                .map(|(key, bytes)| (key.clone(), spec(bytes))),
        );
        resources.insert(HELPER.into(), helper_spec());
        let mut manifest =
            source_app_profile::manifest_for("customer.report", "report", APP, resources).unwrap();
        let runtime = manifest.runtimes.get_mut("python").unwrap();
        runtime.build_id = BUNDLED_BUILD_ID.into();
        let Provisioning::Bundled { source, .. } = &mut runtime.provisioning else {
            unreachable!()
        };
        source.variant = VARIANT.into();
        manifest
    }

    #[test]
    fn metadata_profiles_preserve_legacy_identity_and_provider_checks() {
        let files = contents();
        let bundled = bundled_manifest(&files);
        admit_bundled(&bundled).unwrap();
        assert!(source_app_profile::admit(&bundled).is_err());
        assert_eq!(
            source_app_profile::fixed_specs().unwrap()[LIBRARY],
            bundled.resources[LIBRARY]
        );
        assert_eq!(
            source_app_profile::fixed_specs().unwrap()[STDLIB],
            bundled.resources[STDLIB]
        );
        assert_eq!(
            source_app_profile::fixed_specs().unwrap()[import_profile::IMPORTER],
            bundled.resources[import_profile::IMPORTER]
        );
        for install in [false, true] {
            let manifest = host_manifest(&files, install);
            let config = if install {
                admit_install_host(&manifest)
            } else {
                admit_host(&manifest)
            }
            .unwrap();
            assert_eq!(config.prefix, "/missing Python metadata provider");
            assert!(host_source_app_profile::admit(&manifest).is_err());
            assert!(install_host_source_app_profile::admit(&manifest).is_err());
            assert!(
                if install {
                    admit_host(&manifest)
                } else {
                    admit_install_host(&manifest)
                }
                .is_err()
            );
        }
        assert_eq!(limits_bundled(), source_app_profile::limits());
        assert_eq!(limits_host(), host_source_app_profile::limits());
        let mut legacy =
            declaration(&bundled, BUNDLED_BUILD_ID, source_app_profile::BUILD_ID).unwrap();
        let Provisioning::Bundled { source, .. } =
            &mut legacy.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        source.variant = source_app_profile::VARIANT.into();
        source_app_profile::admit(&legacy).unwrap();
        assert!(admit_bundled(&legacy).is_err());
    }

    #[test]
    fn metadata_admission_rejects_helper_provider_abi_and_inventory_drift() {
        for mode in 0..8 {
            let mut manifest = host_manifest(&contents(), false);
            match mode {
                0 => {
                    manifest.resources.remove(HELPER);
                }
                1 => manifest.resources.get_mut(HELPER).unwrap().sha256 = digest(b"changed"),
                2 => manifest.resources.get_mut(HELPER).unwrap().compression = Compression::Stored,
                3 => {
                    let Provisioning::Host {
                        runtime_library, ..
                    } = &mut manifest.runtimes.get_mut("python").unwrap().provisioning
                    else {
                        unreachable!()
                    };
                    runtime_library.push_str(".changed");
                }
                4 => {
                    let RuntimeAbi::Python { debug, .. } =
                        &mut manifest.runtimes.get_mut("python").unwrap().abi
                    else {
                        unreachable!()
                    };
                    *debug = true;
                }
                5 => manifest.targets.get_mut("linux-arm64").unwrap().arch = Architecture::X86_64,
                6 => {
                    manifest
                        .resources
                        .insert(LIBRARY.into(), spec(b"unexpected host library"));
                }
                _ => {
                    manifest
                        .resources
                        .insert("app/python/os.py".into(), spec(b""));
                }
            }
            assert!(admit_host(&manifest).is_err(), "{mode}");
        }
        let original = bundled_manifest(&contents());
        for key in [
            LIBRARY,
            STDLIB,
            import_profile::IMPORTER,
            "stdlib/importlib/metadata/__init__.py",
        ] {
            let mut manifest = original.clone();
            manifest.resources.get_mut(key).unwrap().sha256 = digest(b"changed");
            assert!(admit_bundled(&manifest).is_err(), "{key}");
        }
        let mut manifest = original;
        let Provisioning::Bundled { source, .. } =
            &mut manifest.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        source.variant = source_app_profile::VARIANT.into();
        assert!(admit_bundled(&manifest).is_err());
    }

    #[test]
    fn metadata_declarations_bound_required_files_and_top_level_layout() {
        for mode in 0..8 {
            let mut manifest = host_manifest(&contents(), false);
            match mode {
                0 => {
                    manifest.resources.remove(METADATA);
                }
                1 => {
                    manifest.resources.remove(RECORD);
                }
                2 => manifest.resources.get_mut(METADATA).unwrap().size = MAX_METADATA + 1,
                3 => manifest.resources.get_mut(RECORD).unwrap().size = MAX_RECORD + 1,
                4 => {
                    manifest
                        .resources
                        .get_mut(&format!("{ROOT}{DIRECTORY}/top_level.txt"))
                        .unwrap()
                        .size = MAX_METADATA + 1
                }
                5 => {
                    manifest.resources.insert(
                        "app/python/nested/other-1.dist-info/METADATA".into(),
                        spec(b""),
                    );
                }
                6 => {
                    manifest
                        .resources
                        .insert("app/python/other.dist-info/METADATA".into(), spec(b""));
                }
                _ => {
                    manifest
                        .resources
                        .insert(format!("{ROOT}{DIRECTORY}/code.py"), spec(b""));
                }
            }
            assert!(admit_host(&manifest).is_err(), "{mode}");
        }
        let mut files = contents();
        for index in 0..MAX_DISTRIBUTIONS {
            files.insert(
                format!("{ROOT}extra{index}-1.dist-info/METADATA"),
                Vec::new(),
            );
            files.insert(format!("{ROOT}extra{index}-1.dist-info/RECORD"), Vec::new());
        }
        assert!(
            admit_host(&host_manifest(&files, false))
                .unwrap_err()
                .contains("count exceeds")
        );
    }

    #[test]
    fn original_host_manifest_cap_includes_helper_and_new_build_identity() {
        for install in [false, true] {
            let mut manifest = host_manifest(&contents(), install);
            let padding = vec!["a".repeat(240); 8].join("/");
            for index in 0..560 {
                manifest
                    .resources
                    .insert(format!("app/assets/{index:04}/{padding}"), spec(b""));
            }
            let cap = limits_host().max_manifest_bytes as usize;
            let oversized = manifest.to_json().unwrap().len();
            assert!(oversized > cap);
            let first_key = format!("app/assets/0000/{padding}");
            manifest.resources.remove(&first_key);
            let entry_bytes = oversized - manifest.to_json().unwrap().len();
            let removals = (oversized - cap) / entry_bytes + 1;
            for index in 1..removals {
                manifest
                    .resources
                    .remove(&format!("app/assets/{index:04}/{padding}"));
            }
            let current = manifest.to_json().unwrap().len();
            assert!(current <= cap);
            let last_key = format!("app/assets/0559/{padding}");
            let target_key_bytes = last_key.len() + cap + 1 - current;
            let mut tuned_key = String::from("app/assets/tuned/");
            while target_key_bytes - tuned_key.len() > 255 {
                tuned_key.push_str(&"a".repeat(240));
                tuned_key.push('/');
            }
            tuned_key.push_str(&"a".repeat(target_key_bytes - tuned_key.len()));
            assert!(tuned_key.len() <= 4096 - "origin\t".len());
            manifest.resources.remove(&last_key);
            manifest.resources.insert(tuned_key, spec(b""));
            assert_eq!(manifest.to_json().unwrap().len(), cap + 1);

            // The same declaration with only the helper removed and historical
            // identity restored passes the old policy: that projected check
            // cannot enforce the original manifest's byte count.
            let mut legacy = manifest.clone();
            legacy.resources.remove(HELPER);
            legacy.runtimes.get_mut("python").unwrap().build_id = if install {
                install_host_source_app_profile::BUILD_ID
            } else {
                host_source_app_profile::BUILD_ID
            }
            .into();
            assert!(legacy.to_json().unwrap().len() <= cap);
            if install {
                install_host_source_app_profile::admit(&legacy).unwrap();
                assert!(
                    admit_install_host(&manifest)
                        .unwrap_err()
                        .contains("original distribution metadata manifest exceeds")
                );
            } else {
                host_source_app_profile::admit(&legacy).unwrap();
                assert!(
                    admit_host(&manifest)
                        .unwrap_err()
                        .contains("original distribution metadata manifest exceeds")
                );
            }
        }
    }

    #[test]
    fn verifies_crlf_metadata_quoted_csv_sha256_sizes_and_generic_fields() {
        verify_contents(&contents()).unwrap();
        assert_eq!(
            record_hash(b""),
            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        assert_eq!(
            metadata_identity(
                "nAmE: A..__B\nVERSION: 1!2.0+local\nCustom: anything\n continuation\n\nbody"
            )
            .unwrap(),
            ("a-b".into(), "1!2.0+local".into())
        );
        assert_eq!(
            record_rows("\"path,with\"\"quote\",,\n").unwrap(),
            [["path,with\"quote".to_owned(), String::new(), String::new()]]
        );
        let mut files = contents();
        let record = text(&files, RECORD).unwrap().to_owned();
        let rows = record_rows(&record).unwrap();
        files.insert(
            RECORD.into(),
            rows.into_iter()
                .map(|[path, _, _]| format!("\"{}\",,\n", path.replace('"', "\"\"")))
                .collect::<String>()
                .into_bytes(),
        );
        verify_contents(&files).unwrap();
    }

    #[test]
    fn rejects_missing_duplicate_folded_and_invalid_identity_headers() {
        for metadata in [
            "Name: customer\n",
            "Version: 1\n",
            "Name: customer\nName: customer\nVersion: 1\n",
            "Name: customer\nVersion: 1\nversion: 1\n",
            "Name: customer\n continuation\nVersion: 1\n",
            "Name: customer\nVersion: 1\n continuation\n",
            " continuation\nName: customer\nVersion: 1\n",
            "Name customer\nVersion: 1\n",
            "Name : customer\nVersion: 1\n",
            "Name: café\nVersion: 1\n",
            "Name: customer/name\nVersion: 1\n",
            "Name: customer\nVersion: ../1\n",
            "Name: customer\rbroken\nVersion: 1\n",
        ] {
            assert!(metadata_identity(metadata).is_err(), "{metadata:?}");
        }
        for metadata in [
            b"Name: Other\nVersion: 1.2\n".as_slice(),
            b"Name: Customer_Demo\nVersion: 1.3\n",
            b"Name: Customer_Demo\nVersion: 1.2\n\n\xff",
        ] {
            let mut files = contents();
            files.insert(METADATA.into(), metadata.to_vec());
            assert!(verify_contents(&files).is_err());
        }
    }

    #[test]
    fn rejects_ambiguous_distributions_and_shared_record_ownership() {
        let mut files = contents();
        files.insert(
            "app/python/customer.demo-2.dist-info/METADATA".into(),
            b"Name: customer-demo\nVersion: 2\n".to_vec(),
        );
        files.insert(
            "app/python/customer.demo-2.dist-info/RECORD".into(),
            b"customer.demo-2.dist-info/METADATA,,\ncustomer.demo-2.dist-info/RECORD,,\n".to_vec(),
        );
        assert!(
            verify_contents(&files)
                .unwrap_err()
                .contains("duplicate normalized")
        );
        files.remove("app/python/customer.demo-2.dist-info/METADATA");
        files.remove("app/python/customer.demo-2.dist-info/RECORD");
        files.insert(
            "app/python/another-1.dist-info/METADATA".into(),
            b"Name: another\nVersion: 1\n".to_vec(),
        );
        files.insert("app/python/another-1.dist-info/RECORD".into(), b"another-1.dist-info/METADATA,,\nanother-1.dist-info/RECORD,,\ncustomer/__init__.py,,\n".to_vec());
        assert!(
            verify_contents(&files)
                .unwrap_err()
                .contains("same RECORD file")
        );
    }

    #[test]
    fn rejects_csv_path_hash_size_and_metadata_coverage_errors() {
        let original = contents();
        let record = text(&original, RECORD).unwrap();
        for suffix in [
            "customer/__init__.py,,\n",
            "../outside,,\n",
            "/absolute,,\n",
            "customer/../outside,,\n",
            "missing.py,,\n",
            "another-1.dist-info/METADATA,,\n",
            "\"customer/data\nline\",,\n",
            "\"unterminated,,\n",
            "customer/__init__.py,hash,size,extra\n",
            "customer/__init__.py\n",
            "\n",
            "\"customer/__init__.py\"garbage,,\n",
            "customer/__init__.py,,\r",
        ] {
            let mut files = original.clone();
            files.insert(RECORD.into(), format!("{record}{suffix}").into_bytes());
            assert!(verify_contents(&files).is_err(), "{suffix:?}");
        }
        for replacement in [
            format!(
                "customer/__init__.py,sha256=invalid,{}",
                original["app/python/customer/__init__.py"].len()
            ),
            "customer/__init__.py,sha512=invalid,".into(),
            "customer/__init__.py,,999".into(),
            "customer/__init__.py,,+12".into(),
            "customer/__init__.py,,18446744073709551616".into(),
        ] {
            let mut files = original.clone();
            let rows = record_rows(record).unwrap();
            let mut changed = String::new();
            for [path, hash, size] in rows {
                if path == "customer/__init__.py" {
                    changed.push_str(&replacement);
                    changed.push('\n');
                } else {
                    changed.push_str(&format!("\"{path}\",{hash},{size}\n"));
                }
            }
            files.insert(RECORD.into(), changed.into_bytes());
            assert!(verify_contents(&files).is_err(), "{replacement}");
        }
        for mode in 0..5 {
            let mut files = original.clone();
            match mode {
                0 => files.insert(
                    RECORD.into(),
                    format!("{DIRECTORY}/METADATA,,\n").into_bytes(),
                ),
                1 => files.insert(
                    RECORD.into(),
                    record
                        .replace(
                            &format!("{DIRECTORY}/RECORD,,"),
                            &format!("{DIRECTORY}/RECORD,,1"),
                        )
                        .into_bytes(),
                ),
                2 => files.insert(format!("{ROOT}{DIRECTORY}/extra.txt"), b"unlisted".to_vec()),
                3 => files.insert(
                    format!("{ROOT}{DIRECTORY}/entry_points.txt"),
                    b"\xff".to_vec(),
                ),
                _ => files.insert(RECORD.into(), vec![b'x'; MAX_RECORD as usize + 1]),
            };
            assert!(verify_contents(&files).is_err(), "{mode}");
        }
        assert!(
            record_rows(&"a,,\n".repeat(MAX_ROWS + 1))
                .unwrap_err()
                .contains("1024")
        );
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "glue-python-metadata-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory)
        }
        fn archive(&self, files: &BTreeMap<String, Vec<u8>>, install: bool) -> Archive<File> {
            let path = self.0.join("metadata.glue");
            write_archive(
                File::create(&path).unwrap(),
                &host_manifest(files, install),
                files,
            )
            .unwrap();
            Archive::open_with_limits(File::open(path).unwrap(), profile::archive_limits()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn archive_metadata_verifies_and_helper_appends_before_any_host_access() {
        let fixture = Fixture::new();
        for install in [false, true] {
            let files = contents();
            let payload = if install {
                read_install_host(fixture.archive(&files, true))
            } else {
                read_host(fixture.archive(&files, false))
            }
            .unwrap();
            assert_eq!(payload.config.prefix, "/missing Python metadata provider");
            let mut bootstrap = host_source_app_profile::PRELUDE.to_vec();
            bootstrap.extend(import_profile::BOOTSTRAP);
            bootstrap.extend(BOOTSTRAP);
            assert_eq!(payload.bootstrap, bootstrap);
            assert!(!payload.resources.contains_key(HELPER));
            assert_eq!(payload.resources[METADATA], files[METADATA]);
            let mut broken = files;
            broken.insert(
                RECORD.into(),
                format!("{DIRECTORY}/METADATA,,\n").into_bytes(),
            );
            let failure = if install {
                read_install_host(fixture.archive(&broken, true))
            } else {
                read_host(fixture.archive(&broken, false))
            }
            .err()
            .unwrap();
            assert!(failure.contains("missing metadata member"), "{failure}");
        }
    }
}
