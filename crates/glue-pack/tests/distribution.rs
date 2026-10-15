use glue_format::*;
use glue_pack::distribution::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "glue-dist-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn input() -> DistributionInput {
    DistributionInput {
        app_id: "ordinary-project".into(),
        entrypoint: "main.lua".into(),
        runtime: RuntimeDescriptor {
            implementation: RuntimeImplementation::Lua,
            version: "5.4.9".into(),
            target: "aarch64-apple-darwin".into(),
            abi: RuntimeAbi::Lua {
                version: RuntimeVersion {
                    major: 5,
                    minor: 4,
                    patch: 9,
                },
                integer_bits: 64,
                number: LuaNumber::Float64,
            },
            provider: RuntimeProvider::Bundled,
            executable: "runtime/lua".into(),
            inputs: BTreeMap::from([("runtime".into(), InputIdentity::of(b"helper"))]),
            requirements: BTreeSet::new(),
        },
        launch: RuntimeLaunchSpec {
            executable: "runtime/lua".into(),
            args: vec!["run".into(), "{archive}".into()],
            environment: BTreeMap::new(),
            clear_environment: true,
        },
        resources: BTreeMap::from([("main.lua".into(), b"print('hello')".to_vec())]),
        payloads: BTreeMap::from([(
            "runtime/lua".into(),
            PayloadSource::Bytes {
                bytes: b"helper".to_vec(),
                mode: 0o755,
            },
        )]),
        native: NativeInventory::default(),
        omissions: BTreeMap::new(),
        notices: "fixture notice\n".into(),
        options: BTreeMap::new(),
    }
}
fn launcher(root: &Path) -> PathBuf {
    let p = root.join("launcher");
    fs::write(&p, b"launcher").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}
#[test]
fn deterministic_complete_relocatable_tree_and_accounting() {
    let t = Temp::new();
    let l = launcher(&t.0);
    let a = t.0.join("one");
    let b = t.0.join("two");
    let r1 = build(input(), &l, &a, DistributionLimits::default()).unwrap();
    let r2 = build(input(), &l, &b, DistributionLimits::default()).unwrap();
    assert_eq!(r1, r2);
    for p in [
        "app.glue",
        "glue",
        "runtime/lua",
        "licenses/NOTICE",
        "glue.lock.json",
        "build-report.json",
    ] {
        assert_eq!(fs::read(a.join(p)).unwrap(), fs::read(b.join(p)).unwrap());
    }
    assert_eq!(r1.sizes.deployed_files, 6);
    assert_eq!(r1.sizes.deployed_directories, 2);
    let actual: u64 = collect_tree(&a, None, 100)
        .unwrap()
        .values()
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    assert_eq!(actual, r1.sizes.payload_bytes + r1.sizes.archive_bytes);
    let lock: BuildLock =
        serde_json::from_slice(&fs::read(a.join("glue.lock.json")).unwrap()).unwrap();
    assert!(lock.inputs.contains_key("archive:main.lua"));
    let mut archive = Archive::open(fs::File::open(a.join("app.glue")).unwrap()).unwrap();
    archive.verify_all().unwrap();
    assert!(!archive.manifest().resources.contains_key("runtime/lua"));
}
#[test]
fn all_input_failures_preserve_existing_outputs_and_leave_no_staging() {
    let t = Temp::new();
    let l = launcher(&t.0);
    let out = t.0.join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("user-data"), b"retain").unwrap();
    assert_eq!(
        build(input(), &l, &out, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::OutputExists
    );
    assert_eq!(fs::read(out.join("user-data")).unwrap(), b"retain");
    for n in 0..5 {
        let mut i = input();
        match n {
            0 => {
                i.payloads
                    .insert("bad".into(), PayloadSource::File(t.0.join("missing")));
            }
            1 => {
                i.payloads.insert(
                    "../escape".into(),
                    PayloadSource::Bytes {
                        bytes: vec![],
                        mode: 0o644,
                    },
                );
            }
            2 => {
                i.payloads.insert(
                    "runtime/lua/child".into(),
                    PayloadSource::Bytes {
                        bytes: vec![],
                        mode: 0o644,
                    },
                );
            }
            3 => {
                i.payloads.insert(
                    "runtime/escape".into(),
                    PayloadSource::Symlink {
                        target: "../../escape".into(),
                    },
                );
            }
            _ => {
                i.entrypoint = "missing".into();
            }
        }
        let dest = t.0.join(format!("absent-{n}"));
        assert!(build(i, &l, &dest, DistributionLimits::default()).is_err());
        assert!(!dest.exists());
    }
    assert!(!fs::read_dir(&t.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".glue-stage-")
    }));
}
#[test]
fn tree_collection_excludes_outputs_resolves_safe_links_and_rejects_escape() {
    let a = Temp::new();
    let b = Temp::new();
    for root in [&a.0, &b.0] {
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/source"), b"same").unwrap();
    }
    let x = collect_tree(&a.0, None, 10).unwrap();
    let y = collect_tree(&b.0, None, 10).unwrap();
    assert_eq!(x.keys().collect::<Vec<_>>(), y.keys().collect::<Vec<_>>());
    assert_eq!(
        fs::read(&x["nested/source"]).unwrap(),
        fs::read(&y["nested/source"]).unwrap()
    );
    let output = a.0.join("dist");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("old"), b"skip").unwrap();
    assert_eq!(collect_tree(&a.0, Some(&output), 10).unwrap().len(), 1);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("nested/source", a.0.join("safe")).unwrap();
        assert_eq!(collect_tree(&a.0, Some(&output), 10).unwrap().len(), 2);
        std::os::unix::fs::symlink(&b.0, a.0.join("escape")).unwrap();
        assert_eq!(
            collect_tree(&a.0, Some(&output), 10).unwrap_err().code,
            DiagnosticCode::PathEscape
        );
    }
}
#[cfg(unix)]
#[test]
fn internal_symlink_and_permissions_are_preserved() {
    let t = Temp::new();
    let l = launcher(&t.0);
    let mut i = input();
    i.payloads.insert(
        "runtime/alias".into(),
        PayloadSource::Symlink {
            target: "lua".into(),
        },
    );
    let out = t.0.join("out");
    build(i, &l, &out, DistributionLimits::default()).unwrap();
    assert_eq!(
        fs::read_link(out.join("runtime/alias")).unwrap(),
        Path::new("lua")
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(out.join("runtime/lua"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[cfg(target_os = "macos")]
#[test]
fn claimed_normalized_signature_is_verified_at_staged_bundle_path_before_publication() {
    use std::process::Command;
    let t = Temp::new();
    let source = t.0.join("image.c");
    let image = t.0.join("image");
    fs::write(&source, "int main(void){return 0;}\n").unwrap();
    assert!(
        Command::new("/usr/bin/cc")
            .arg(&source)
            .arg("-o")
            .arg(&image)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&image)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&image)
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(&image).unwrap();
    let launcher = launcher(&t.0);
    let bundle_path = "native/Incomplete.app/Contents/MacOS/Incomplete";
    let prepared = |path: &str, claimed: bool| {
        let mut selected = input();
        selected.payloads.insert(
            path.into(),
            PayloadSource::Bytes {
                bytes: bytes.clone(),
                mode: 0o755,
            },
        );
        selected.native.transformations.push(Transformation {
            path: path.into(),
            input: InputIdentity::of(&bytes),
            output: InputIdentity::of(&bytes),
            edits: vec!["independent signed normalization-output fixture".into()],
            signing: claimed.then(|| "ad_hoc; temporary image verified".into()),
        });
        selected
    };
    // Existing/unsigned inputs gain no new signing requirement without a claim.
    let unchanged = t.0.join("unchanged");
    build(
        prepared(bundle_path, false),
        &launcher,
        &unchanged,
        DistributionLimits::default(),
    )
    .unwrap();
    assert!(
        !Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(unchanged.join(bundle_path))
            .status()
            .unwrap()
            .success()
    );
    let rejected = t.0.join("rejected");
    let failure = build(
        prepared(bundle_path, true),
        &launcher,
        &rejected,
        DistributionLimits::default(),
    )
    .unwrap_err();
    assert_eq!(failure.code, DiagnosticCode::TransformationRequired);
    assert!(failure.message.contains(bundle_path));
    assert!(failure.message.contains("staged path"));
    assert!(!rejected.exists());
    assert!(!fs::read_dir(&t.0).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".glue-stage-")
    }));
    let accepted = t.0.join("accepted");
    let standalone = "native/bin/image";
    build(
        prepared(standalone, true),
        &launcher,
        &accepted,
        DistributionLimits::default(),
    )
    .unwrap();
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(accepted.join(standalone))
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&image).unwrap(), bytes);
}
