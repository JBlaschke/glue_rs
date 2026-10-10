//! Exact unstripped install-only transform reviewed at the pinned PBS revision.
use crate::{
    archive::{EntryKind, Inventory},
    strict_json,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const REVIEWED_REVISION: &str = "ccc07c40c2731bfb459c119f2388f65a5a470de6";
const DROP_EXTENSIONS: [&str; 9] = [
    "_ctypes_test",
    "_testbuffer",
    "_testcapi",
    "_testexternalinspection",
    "_testimportmultiple",
    "_testinternalcapi",
    "_testlimitedcapi",
    "_testmultiphase",
    "_testsinglephase",
];

#[derive(Debug, Serialize)]
pub struct PairReport {
    pub filter_revision: String,
    pub matched_entries: usize,
    pub omitted_entries: BTreeMap<String, Vec<String>>,
}

pub fn compare(
    full: &Inventory,
    install: &Inventory,
    stdlib: &str,
    revision: &str,
) -> Result<PairReport, String> {
    if revision != REVIEWED_REVISION {
        return Err("PBS install-only filtering has not been reviewed for this revision".into());
    }
    let json = strict_json(full.metadata.as_ref().ok_or("missing full metadata")?)?;
    let packages = json["python_stdlib_test_packages"]
        .as_array()
        .ok_or("missing stdlib test package filter metadata")?;
    if packages.len() > 64 {
        return Err("too many stdlib test package filters".into());
    }
    let mut test_prefixes = Vec::new();
    let mut seen = BTreeSet::new();
    for value in packages {
        let name = value.as_str().ok_or("invalid stdlib test package filter")?;
        if name.len() > 256
            || !seen.insert(name)
            || name.split('.').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            })
        {
            return Err("invalid or duplicate stdlib test package filter".into());
        }
        test_prefixes.push(format!("{stdlib}/{}/", name.replace('.', "/")));
    }
    let extensions = json["build_info"]["extensions"]
        .as_object()
        .ok_or("missing extension filter metadata")?;
    let mut dropped_extensions = BTreeSet::new();
    for name in DROP_EXTENSIONS {
        if let Some(variants) = extensions.get(name) {
            let variants = variants
                .as_array()
                .ok_or("invalid test extension variants")?;
            if variants.len() > 16 {
                return Err("too many test extension variants".into());
            }
            for variant in variants {
                if let Some(path) = variant.get("shared_lib") {
                    let relative = path.as_str().ok_or("invalid test extension path")?;
                    let path = format!("python/{relative}");
                    if !path.starts_with("python/install/")
                        || relative.split('/').any(|part| {
                            part.is_empty()
                                || part == "."
                                || part == ".."
                                || part.contains('\\')
                                || part.contains(':')
                                || part.chars().any(char::is_control)
                        })
                    {
                        return Err("unsafe test extension filter path".into());
                    }
                    let entry = full
                        .entries
                        .get(&path)
                        .ok_or("test extension filter names missing file")?;
                    if entry.kind != EntryKind::RegularFile {
                        return Err("test extension filter must name a regular file".into());
                    }
                    dropped_extensions.insert(path);
                }
            }
        }
    }
    let mut expected = BTreeMap::new();
    let mut omitted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, entry) in &full.entries {
        let reason = if !path.starts_with("python/install/") {
            Some("outside_install")
        } else if path.contains("/libpython") && path.ends_with(".a") {
            Some("libpython_static_archive")
        } else if test_prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            Some("stdlib_test_package")
        } else if dropped_extensions.contains(path) {
            Some("test_extension")
        } else {
            None
        };
        if let Some(reason) = reason {
            omitted.entry(reason.into()).or_default().push(path.clone());
            continue;
        }
        let normalized = format!("python/{}", path.strip_prefix("python/install/").unwrap());
        let mut normalized_entry = entry.clone();
        if let Some(resolved) = &entry.resolved_target {
            normalized_entry.resolved_target = Some(format!(
                "python/{}",
                resolved
                    .strip_prefix("python/install/")
                    .ok_or("install-only link targets something outside the installation")?
            ));
        }
        expected.insert(normalized, normalized_entry);
    }
    if expected.len() != install.entries.len() {
        return Err(format!(
            "PBS install-only inventory differs: expected {} entries, got {}",
            expected.len(),
            install.entries.len()
        ));
    }
    for (path, entry) in expected {
        if install.entries.get(&path) != Some(&entry) {
            return Err(format!(
                "PBS install-only content/mode/type/link mismatch at {path:?}"
            ));
        }
    }
    Ok(PairReport {
        filter_revision: revision.into(),
        matched_entries: install.entries.len(),
        omitted_entries: omitted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Entry;
    use sha2::{Digest, Sha256};

    fn entry() -> Entry {
        Entry {
            kind: EntryKind::RegularFile,
            size: 1,
            sha256: Some(crate::hex_digest(&Sha256::digest(b"a"))),
            mode: 0o644,
            link_target: None,
            resolved_target: None,
        }
    }
    fn inventory(entries: BTreeMap<String, Entry>, metadata: Option<Vec<u8>>) -> Inventory {
        Inventory {
            entries,
            metadata,
            decompressed_bytes: 0,
            binary_prefixes: BTreeMap::new(),
        }
    }

    #[test]
    fn filters_only_reviewed_omissions_and_compares_all_remaining_bytes() {
        let json=br#"{"python_stdlib_test_packages":["test"],"build_info":{"extensions":{"_testcapi":[{"shared_lib":"install/lib/python3.13/lib-dynload/_testcapi.so"}]}}}"#.to_vec();
        let full = inventory(
            [
                "python/PYTHON.json",
                "python/install/lib/libpython3.13.a",
                "python/install/lib/python3.13/test/a.py",
                "python/install/lib/python3.13/lib-dynload/_testcapi.so",
                "python/install/lib/python3.13/keep.py",
            ]
            .into_iter()
            .map(|path| (path.into(), entry()))
            .collect(),
            Some(json),
        );
        let mut install = inventory(
            BTreeMap::from([("python/lib/python3.13/keep.py".into(), entry())]),
            None,
        );
        let report = compare(
            &full,
            &install,
            "python/install/lib/python3.13",
            REVIEWED_REVISION,
        )
        .unwrap();
        assert_eq!(report.matched_entries, 1);
        assert_eq!(report.omitted_entries.len(), 4);
        install
            .entries
            .get_mut("python/lib/python3.13/keep.py")
            .unwrap()
            .sha256 = Some("0".repeat(64));
        assert!(
            compare(
                &full,
                &install,
                "python/install/lib/python3.13",
                REVIEWED_REVISION
            )
            .unwrap_err()
            .contains("mismatch")
        );
    }

    #[test]
    fn rejects_unknown_filter_revision_added_and_missing_entries() {
        let full = inventory(
            BTreeMap::from([("python/install/a".into(), entry())]),
            Some(br#"{"python_stdlib_test_packages":[],"build_info":{"extensions":{}}}"#.to_vec()),
        );
        let install = inventory(BTreeMap::new(), None);
        assert!(
            compare(&full, &install, "python/install/lib/python3.13", "main")
                .unwrap_err()
                .contains("reviewed")
        );
        assert!(
            compare(
                &full,
                &install,
                "python/install/lib/python3.13",
                REVIEWED_REVISION
            )
            .unwrap_err()
            .contains("inventory")
        );
        let install = inventory(
            BTreeMap::from([
                ("python/a".into(), entry()),
                ("python/extra".into(), entry()),
            ]),
            None,
        );
        assert!(
            compare(
                &full,
                &install,
                "python/install/lib/python3.13",
                REVIEWED_REVISION
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_escaping_and_duplicate_metadata_filters() {
        for packages in [
            serde_json::json!(["../test"]),
            serde_json::json!(["test", "test"]),
        ] {
            let full=inventory(BTreeMap::new(),Some(serde_json::to_vec(&serde_json::json!({"python_stdlib_test_packages":packages,"build_info":{"extensions":{}}})).unwrap()));
            assert!(
                compare(
                    &full,
                    &inventory(BTreeMap::new(), None),
                    "python/install/lib/python3.13",
                    REVIEWED_REVISION
                )
                .is_err()
            );
        }
    }
}
