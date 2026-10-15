#![cfg(feature = "python")]
use glue_format::*;
use glue_pack::{
    distribution::{self, DistributionInput, DistributionLimits, PayloadSource},
    python::{
        discovery::{ResolvedEnvironment, RuntimeMetadata},
        inventory::{self, InventoryOptions, PythonEntry},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static SERIAL: AtomicUsize = AtomicUsize::new(0);
fn fixture() -> (PathBuf, ResolvedEnvironment, InventoryOptions) {
    let root = std::env::temp_dir().join(format!(
        "glue python inventory café {}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mvp/python-env");
    for (relative, path) in distribution::collect_tree(&fixture, None, 100).unwrap() {
        let dest = root.join(relative);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(path, dest).unwrap();
    }
    let runtime = RuntimeMetadata {
        executable: "/not/executed".into(),
        prefix: "/not/executed".into(),
        stdlib: "/not/executed/lib/python3.13".into(),
        version: [3, 13, 1],
        version_text: "3.13.1".into(),
        implementation: "cpython".into(),
        machine: std::env::consts::ARCH.into(),
        system: if cfg!(target_os = "macos") {
            "Darwin"
        } else {
            "Linux"
        }
        .into(),
        soabi: "cpython-313".into(),
        gil_disabled: false,
        debug: false,
        framework: String::new(),
        extension_suffixes: vec![".cpython-313-darwin.so".into(), ".so".into()],
    };
    let descriptor = RuntimeDescriptor {
        implementation: RuntimeImplementation::Cpython,
        version: "3.13.1".into(),
        target: glue_pack::python::discovery::current_target().unwrap(),
        abi: RuntimeAbi::Python {
            version: RuntimeVersion {
                major: 3,
                minor: 13,
                patch: 1,
            },
            gil: GilMode::Conventional,
            debug: false,
        },
        provider: RuntimeProvider::Host,
        executable: "/not/executed".into(),
        inputs: BTreeMap::new(),
        requirements: BTreeSet::new(),
    };
    let environment = ResolvedEnvironment {
        environment: root.join("env"),
        runtime,
        descriptor,
        site_packages: vec![root.join("site")],
        pyvenv: BTreeMap::new(),
        console_scripts: BTreeMap::from([("sample".into(), "samplepkg:main".into())]),
    };
    let options = InventoryOptions::new(root.join("project"), PythonEntry::File("main.py".into()));
    (root, environment, options)
}

#[test]
fn preserves_metadata_resources_namespace_and_hands_native_files_forward() {
    let (root, environment, options) = fixture();
    fs::create_dir_all(root.join("site/extra")).unwrap();
    fs::write(root.join("site/internal.pth"), "# safe path\nextra\n").unwrap();
    fs::write(root.join("site/unowned.dat"), "preserved").unwrap();
    fs::write(root.join("site/module.so"), b"\x7fELFprebuilt").unwrap();
    let found = inventory::collect(&environment, &options).unwrap();
    assert!(
        found
            .resources
            .contains_key("app/site/0/samplepkg/resource.txt")
    );
    assert!(
        found
            .index
            .import_roots
            .contains(&"app/site/0/extra".into())
    );
    assert!(found.unowned.contains(&"app/site/0/unowned.dat".into()));
    assert!(found.native_files.contains_key("app/site/0/module.so"));
    assert!(!found.resources.contains_key("app/site/0/module.so"));
    fs::write(
        root.join("site/internal.pth"),
        "import os; print('not executed')\n",
    )
    .unwrap();
    assert!(
        inventory::collect(&environment, &options)
            .unwrap_err()
            .contains("executable .pth")
    );
    fs::write(root.join("site/internal.pth"), "../project\n").unwrap();
    assert!(
        inventory::collect(&environment, &options)
            .unwrap_err()
            .contains("escapes")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn record_integrity_and_source_escape_reject() {
    let (root, environment, options) = fixture();
    fs::write(
        root.join("site/samplepkg-1.0.dist-info/RECORD"),
        "samplepkg/resource.txt,sha256=wrong,\n",
    )
    .unwrap();
    assert!(
        inventory::collect(&environment, &options)
            .unwrap_err()
            .contains("SHA-256")
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", root.join("project/escaped")).unwrap();
        assert!(
            inventory::collect(&environment, &options)
                .unwrap_err()
                .contains("symlink escapes")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires a supplied native GLUE_TEST_PYTHON for host importer execution"]
fn verified_archive_imports_work_after_project_and_environment_are_removed() {
    let python = std::env::var_os("GLUE_TEST_PYTHON").expect("supply GLUE_TEST_PYTHON");
    let (root, mut environment, options) = fixture();
    let selected = fs::canonicalize(PathBuf::from(&python)).unwrap();
    let facts =
        glue_pack::python::discovery::probe(&selected, std::time::Duration::from_secs(15)).unwrap();
    environment.descriptor.executable = selected.to_string_lossy().into_owned();
    environment.descriptor.version = facts
        .version
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(".");
    environment.descriptor.abi = RuntimeAbi::Python {
        version: RuntimeVersion {
            major: facts.version[0],
            minor: facts.version[1],
            patch: facts.version[2],
        },
        gil: GilMode::Conventional,
        debug: false,
    };
    environment.descriptor.inputs.insert(
        "runtime-executable".into(),
        InputIdentity::of(&fs::read(&selected).unwrap()),
    );
    let inventory = inventory::collect(&environment, &options).unwrap();
    let bootstrap = format!(
        "{}\nrun_application(sys.argv[1], os.path.dirname(os.path.realpath(sys.argv[0])), sys.argv[2:])\n",
        include_str!("../src/python/importer.py")
    );
    let input = DistributionInput {
        app_id: "python-env".into(),
        entrypoint: "app/project/main.py".into(),
        runtime: environment.descriptor.clone(),
        launch: RuntimeLaunchSpec {
            executable: environment.descriptor.executable.clone(),
            args: vec![],
            environment: BTreeMap::new(),
            clear_environment: true,
        },
        resources: inventory.resources,
        payloads: BTreeMap::from([(
            "bootstrap.py".into(),
            PayloadSource::Bytes {
                bytes: bootstrap.into_bytes(),
                mode: 0o444,
            },
        )]),
        native: NativeInventory::default(),
        omissions: inventory.omissions,
        notices: "fixture".into(),
        options: BTreeMap::new(),
    };
    distribution::build(
        input,
        Path::new("/usr/bin/true"),
        &root.join("output"),
        DistributionLimits::default(),
    )
    .unwrap();
    fs::remove_dir_all(root.join("project")).unwrap();
    fs::remove_dir_all(root.join("site")).unwrap();
    let result = Command::new(python)
        .args(["-I", "-S", "-B"])
        .arg(root.join("output/bootstrap.py"))
        .arg(root.join("output/app.glue"))
        .arg("argument café")
        .env_clear()
        .env("PATH", "")
        .env("HOME", "/dev/null")
        .env("TMPDIR", "/dev/null/blocked")
        .current_dir("/")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "python-env-ok argument café"
    );
    fs::remove_dir_all(root).unwrap();
}
