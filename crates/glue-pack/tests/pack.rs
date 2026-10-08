use glue_format::{Archive, ArchiveLimits, Manifest, digest};
use glue_pack::{PackError, PackLimits, build, build_with_limits};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    manifest: PathBuf,
    resources: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("glue-pack-test-{}-{now}-{id}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let root = directory.join("resource tree Ł with spaces");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("app")).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        let resources = BTreeMap::from([
            ("app/main.lua".to_owned(), b"return 42\n".to_vec()),
            ("assets/empty".to_owned(), Vec::new()),
            (
                "assets/message.txt".to_owned(),
                b"hello from an archive".to_vec(),
            ),
        ]);
        for (path, bytes) in &resources {
            fs::write(root.join(path), bytes).unwrap();
        }
        let specifications: BTreeMap<_, _> = resources.iter().map(|(path, bytes)| (path, json!({
            "size": bytes.len(), "sha256": digest(bytes),
            "compression": if path == "assets/message.txt" { "deflate" } else { "stored" },
        }))).collect();
        let manifest = directory.join("input manifest Ł.json");
        fs::write(&manifest, serde_json::to_vec_pretty(&json!({
            "schema_version": 0, "app_id": "pack.fixture", "entrypoint": "main",
            "targets": {"mac": {"os": "macos", "arch": "aarch64", "minimum_os_version": "14.0",
                "abi": {"family": "darwin"}, "page_sizes": [4096], "cpu_features": []}},
            "resources": specifications,
            "runtimes": {"lua": {"target": "mac", "build_id": "lua-fixture",
                "abi": {"language": "lua", "version": {"major": 5, "minor": 4, "patch": 8},
                    "integer_bits": 64, "number": "float64"},
                "provisioning": {"mode": "host", "runtime_library": "/fixture/liblua.dylib",
                    "stdlib": "/fixture/lua", "discovery": "explicit_paths"}, "required_features": []}},
            "components": {"main": {"runtime": "lua", "entry_point": "app/main.lua", "native_modules": []}},
            "native_modules": {}, "host_imports": {},
        })).unwrap()).unwrap();
        Self {
            directory,
            root,
            manifest,
            resources,
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn edit_manifest(&self, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut manifest = serde_json::from_slice(&fs::read(&self.manifest).unwrap()).unwrap();
        edit(&mut manifest);
        fs::write(&self.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn explicit_inventory_builds_deterministically_and_reports_identities() {
    let fixture = Fixture::new();
    let first = fixture.output("first.glue");
    let second = fixture.output("second.glue");
    // Extra inputs are intentionally excluded; no directory discovery is implied.
    fs::write(
        fixture.root.join("undeclared.txt"),
        b"not part of the manifest",
    )
    .unwrap();
    let report = build(&fixture.manifest, &fixture.root, &first).unwrap();
    let repeated = build(&fixture.manifest, &fixture.root, &second).unwrap();
    assert_eq!(report, repeated);
    let bytes = fs::read(&first).unwrap();
    assert_eq!(bytes, fs::read(&second).unwrap());
    assert_eq!(report.archive_bytes, bytes.len() as u64);
    assert_eq!(report.resource_count, fixture.resources.len());
    assert_eq!(
        report.uncompressed_bytes,
        fixture
            .resources
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(report.archive_sha256, digest(&bytes));
    let mut archive = Archive::open(Cursor::new(&bytes)).unwrap();
    assert_eq!(
        report.manifest_sha256,
        digest(&archive.manifest().to_json().unwrap())
    );
    for (path, expected) in &fixture.resources {
        assert_eq!(archive.read_resource(path).unwrap(), *expected);
    }
    assert!(!archive.entries().contains_key("undeclared.txt"));
}

#[test]
fn archive_survives_relocation_with_spaces_and_unicode() {
    let fixture = Fixture::new();
    let output = fixture.output("first.glue");
    build(&fixture.manifest, &fixture.root, &output).unwrap();
    let relocated = fixture.directory.join("moved elsewhere Ł");
    fs::create_dir(&relocated).unwrap();
    let destination = relocated.join("app renamed Ł with spaces.glue");
    fs::rename(output, &destination).unwrap();
    let mut archive = Archive::open(fs::File::open(destination).unwrap()).unwrap();
    assert_eq!(
        archive.read_resource("app/main.lua").unwrap(),
        fixture.resources["app/main.lua"]
    );
}

#[test]
fn incorrect_input_hash_and_size_fail_before_output_creation() {
    for change_size in [false, true] {
        let fixture = Fixture::new();
        let input = fixture.root.join("app/main.lua");
        let mut bytes = fixture.resources["app/main.lua"].clone();
        if change_size {
            bytes.push(0);
        } else {
            bytes[0] ^= 1;
        }
        fs::write(&input, bytes).unwrap();
        let output = fixture.output("must not exist.glue");
        let error = build(&fixture.manifest, &fixture.root, &output).unwrap_err();
        assert!(matches!(error, PackError::Resource { .. }));
        assert!(error.to_string().contains("app/main.lua"));
        assert!(!output.exists());
    }
}

#[test]
fn input_manifest_and_archive_limits_fail_before_publication() {
    let fixture = Fixture::new();
    let limits = [
        PackLimits {
            max_input_bytes: 1,
            ..PackLimits::default()
        },
        PackLimits {
            archive_limits: ArchiveLimits {
                max_manifest_bytes: 1,
                ..ArchiveLimits::default()
            },
            ..PackLimits::default()
        },
        PackLimits {
            archive_limits: ArchiveLimits {
                max_entry_bytes: 1,
                ..ArchiveLimits::default()
            },
            ..PackLimits::default()
        },
        PackLimits {
            archive_limits: ArchiveLimits {
                max_total_uncompressed_bytes: 1,
                ..ArchiveLimits::default()
            },
            ..PackLimits::default()
        },
        PackLimits {
            archive_limits: ArchiveLimits {
                max_entries: 1,
                ..ArchiveLimits::default()
            },
            ..PackLimits::default()
        },
    ];
    for limits in limits {
        let output = fixture.output("must not exist.glue");
        assert!(matches!(
            build_with_limits(&fixture.manifest, &fixture.root, &output, limits),
            Err(PackError::Limit { .. })
        ));
        assert!(!output.exists());
    }
    // Generated-container limits also apply before the destination is created.
    let output = fixture.output("must not exist.glue");
    let limits = PackLimits {
        archive_limits: ArchiveLimits {
            max_compressed_entry_bytes: 0,
            ..ArchiveLimits::default()
        },
        ..PackLimits::default()
    };
    assert!(matches!(
        build_with_limits(&fixture.manifest, &fixture.root, &output, limits),
        Err(PackError::Archive(_))
    ));
    assert!(!output.exists());
}

#[test]
fn declared_input_budget_is_checked_before_opening_any_resource() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.root.join("app/main.lua")).unwrap();
    let output = fixture.output("must not exist.glue");
    let error = build_with_limits(
        &fixture.manifest,
        &fixture.root,
        &output,
        PackLimits {
            max_input_bytes: 1,
            ..PackLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PackError::Limit {
            limit: "input bytes",
            ..
        }
    ));
    assert!(!output.exists());
}

#[test]
fn invalid_manifest_duplicate_keys_and_schema_fail_before_publication() {
    let fixture = Fixture::new();
    let output = fixture.output("must not exist.glue");
    for bytes in [
        b"{".as_slice(),
        br#"{"schema_version":0,"schema_version":0}"#.as_slice(),
    ] {
        fs::write(&fixture.manifest, bytes).unwrap();
        assert!(matches!(
            build(&fixture.manifest, &fixture.root, &output),
            Err(PackError::Manifest { .. })
        ));
        assert!(!output.exists());
    }
    let fixture = Fixture::new();
    fixture.edit_manifest(|manifest| manifest["schema_version"] = 99.into());
    assert!(matches!(
        build(&fixture.manifest, &fixture.root, &output),
        Err(PackError::Manifest { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn existing_destination_is_preserved() {
    let fixture = Fixture::new();
    let output = fixture.output("existing.glue");
    let original = b"existing user content";
    fs::write(&output, original).unwrap();
    assert!(build(&fixture.manifest, &fixture.root, &output).is_err());
    assert_eq!(fs::read(output).unwrap(), original);
}

#[test]
fn missing_empty_wrong_root_and_nonregular_resources_fail() {
    let fixture = Fixture::new();
    let output = fixture.output("must not exist.glue");
    for root in [
        Path::new(""),
        fixture.manifest.as_path(),
        fixture.directory.as_path(),
        fixture.directory.join("absent").as_path(),
    ] {
        assert!(build(&fixture.manifest, root, &output).is_err());
        assert!(!output.exists());
    }
    fs::remove_file(fixture.root.join("app/main.lua")).unwrap();
    fs::create_dir(fixture.root.join("app/main.lua")).unwrap();
    assert!(matches!(
        build(&fixture.manifest, &fixture.root, &output),
        Err(PackError::Resource { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn manifest_limit_rejects_oversized_input_before_json_decoding() {
    let fixture = Fixture::new();
    let output = fixture.output("must not exist.glue");
    let limits = PackLimits {
        archive_limits: ArchiveLimits {
            max_manifest_bytes: 4,
            ..ArchiveLimits::default()
        },
        ..PackLimits::default()
    };
    fs::write(&fixture.manifest, b"malformed and oversized JSON").unwrap();
    let error = build_with_limits(&fixture.manifest, &fixture.root, &output, limits).unwrap_err();
    assert!(matches!(
        error,
        PackError::Limit {
            limit: "manifest bytes",
            ..
        }
    ));
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn resource_and_directory_symlinks_are_rejected_before_output_creation() {
    use std::os::unix::fs::symlink;
    for directory in [false, true] {
        let fixture = Fixture::new();
        let output = fixture.output("must not exist.glue");
        if directory {
            let app = fixture.root.join("app");
            let moved = fixture.directory.join("actual app");
            fs::rename(&app, &moved).unwrap();
            symlink(&moved, &app).unwrap();
        } else {
            let entry = fixture.root.join("app/main.lua");
            let moved = fixture.directory.join("actual main.lua");
            fs::rename(&entry, &moved).unwrap();
            symlink(&moved, &entry).unwrap();
        }
        let error = build(&fixture.manifest, &fixture.root, &output).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert!(!output.exists());
    }
}

#[cfg(unix)]
#[test]
fn output_symlinks_and_root_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let original = fixture.output("user-file");
    let output = fixture.output("existing-symlink.glue");
    fs::write(&original, b"preserve me").unwrap();
    symlink(&original, &output).unwrap();
    assert!(build(&fixture.manifest, &fixture.root, &output).is_err());
    assert_eq!(fs::read(&original).unwrap(), b"preserve me");
    assert!(
        fs::symlink_metadata(output)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let root = fixture.output("root-symlink");
    symlink(&fixture.root, &root).unwrap();
    let output = fixture.output("must not exist.glue");
    assert!(matches!(
        build(&fixture.manifest, &root, &output),
        Err(PackError::Root { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn manifest_resource_paths_cannot_escape_root() {
    let fixture = Fixture::new();
    fixture.edit_manifest(|manifest| {
        let spec = manifest["resources"]["assets/empty"].take();
        manifest["resources"]
            .as_object_mut()
            .unwrap()
            .insert("../outside".to_owned(), spec);
        manifest["resources"]
            .as_object_mut()
            .unwrap()
            .remove("assets/empty");
    });
    let output = fixture.output("must not exist.glue");
    assert!(matches!(
        build(&fixture.manifest, &fixture.root, &output),
        Err(PackError::Manifest { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn input_manifest_remains_valid_and_unmodified() {
    let fixture = Fixture::new();
    let original = fs::read(&fixture.manifest).unwrap();
    Manifest::from_json(&original).unwrap();
    build(
        &fixture.manifest,
        &fixture.root,
        &fixture.output("new.glue"),
    )
    .unwrap();
    assert_eq!(fs::read(&fixture.manifest).unwrap(), original);
}
