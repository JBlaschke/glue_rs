#![cfg(feature = "python")]
use glue_format::{Archive, DiagnosticCode, RuntimeProvider};
use glue_pack::python::{
    compact::{self, CompactBuildOptions},
    discovery::{self, DiscoveryOptions},
    inventory::{InventoryOptions, PythonEntry},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "__pycache__" {
            continue;
        }
        let dest = target.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            assert!(
                !dest.exists(),
                "duplicate supplied site input {}",
                dest.display()
            );
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
#[ignore = "requires independent prebuilt wheel trees in GLUE_TEST_NATIVE_SITES, GLUE_TEST_NATIVE_SECONDARY and selected GLUE_TEST_PYTHON"]
fn installed_native_c_cpp_rust_ffi_and_secondary_dependencies_match_source_environment() {
    let python =
        PathBuf::from(std::env::var_os("GLUE_TEST_PYTHON").expect("supply GLUE_TEST_PYTHON"));
    let sources =
        std::env::var_os("GLUE_TEST_NATIVE_SITES").expect("supply GLUE_TEST_NATIVE_SITES");
    let secondary = PathBuf::from(
        std::env::var_os("GLUE_TEST_NATIVE_SECONDARY")
            .expect("supply independent secondary library"),
    );
    let metadata = discovery::probe(&python, Duration::from_secs(15)).unwrap();
    let root = std::env::temp_dir().join(format!("glue-python-native-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(&root).unwrap();
    let environment = root.join("input env");
    let site = environment.join(format!(
        "lib/python{}.{}/site-packages",
        metadata.version[0], metadata.version[1]
    ));
    fs::create_dir_all(environment.join("bin")).unwrap();
    fs::create_dir_all(&site).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        python.canonicalize().unwrap(),
        environment.join("bin/python"),
    )
    .unwrap();
    fs::write(
        environment.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\n",
            metadata.prefix.display()
        ),
    )
    .unwrap();
    for source in std::env::split_paths(&sources) {
        copy_tree(&source, &site);
    }
    fs::create_dir_all(site.join("native_probe")).unwrap();
    fs::write(site.join("native_probe/__init__.py"), "\n").unwrap();
    fs::copy(
        &secondary,
        site.join("native_probe")
            .join(secondary.file_name().unwrap()),
    )
    .unwrap();
    let project = root.join("input project");
    fs::create_dir_all(&project).unwrap();
    let main = project.join("main.py");
    let application = std::env::var_os("GLUE_TEST_NATIVE_APP")
        .map(|p| fs::read(p).unwrap())
        .unwrap_or_else(|| include_bytes!("../../../fixtures/mvp/python-native/main.py").to_vec());
    fs::write(&main, &application).unwrap();
    let original_native = glue_pack::distribution::collect_tree(&site, None, 100_000)
        .unwrap()
        .into_iter()
        .filter(|(name, _)| {
            name.ends_with(".so") || name.ends_with(".dylib") || name.contains(".so.")
        })
        .map(|(name, path)| {
            (
                name,
                glue_format::InputIdentity::of(&fs::read(path).unwrap()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut reference_command = Command::new(&python);
    if std::env::var_os("GLUE_TEST_REFERENCE_LIBRARY_PATH").is_some() {
        reference_command.env("LD_LIBRARY_PATH", &site);
    }
    let reference=reference_command.args(["-I","-S","-B","-c","import sys; sys.path.insert(0,sys.argv[1]); path=sys.argv[2]; sys.argv=[path]; exec(compile(open(path,'rb').read(),path,'exec'),{'__name__':'__main__','__file__':path})"]).arg(&site).arg(&main).env("PYTHONDONTWRITEBYTECODE","1").output().unwrap();
    assert!(
        reference.status.success(),
        "source environment failed: {}",
        String::from_utf8_lossy(&reference.stderr)
    );
    let options = CompactBuildOptions {
        discovery: DiscoveryOptions {
            environment: environment.clone(),
            runtime: None,
            python_version: None,
            target: None,
            inspect_only: false,
        },
        application: InventoryOptions::new(project.clone(), PythonEntry::File("main.py".into())),
        runtime_provider: RuntimeProvider::Bundled,
        native_search: std::env::var_os("GLUE_TEST_NATIVE_SEARCH")
            .map(|s| std::env::split_paths(&s).collect())
            .unwrap_or_default(),
        normalize_native_paths: std::env::var_os("GLUE_TEST_NORMALIZE").is_some(),
        app_id: "python-native".into(),
    };
    let output = root.join("built");
    let first_native = site.join(original_native.keys().next().unwrap());
    let incompatible = site.join("foreign.cpython-399-incompatible.so");
    fs::copy(first_native, &incompatible).unwrap();
    assert_eq!(
        compact::build(
            &options,
            Path::new("/usr/bin/true"),
            &root.join("wrong-abi")
        )
        .unwrap_err()
        .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
    assert!(!root.join("wrong-abi").exists());
    fs::remove_file(incompatible).unwrap();
    fs::create_dir_all(site.join("foreign-1.dist-info")).unwrap();
    fs::write(
        site.join("foreign-1.dist-info/WHEEL"),
        "Wheel-Version: 1.0\nTag: cp399-cp399-any\n",
    )
    .unwrap();
    assert_eq!(
        compact::build(
            &options,
            Path::new("/usr/bin/true"),
            &root.join("wrong-wheel")
        )
        .unwrap_err()
        .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
    fs::remove_dir_all(site.join("foreign-1.dist-info")).unwrap();
    let report = compact::build(&options, Path::new("/usr/bin/true"), &output).unwrap();
    for (name, identity) in &original_native {
        assert_eq!(
            &glue_format::InputIdentity::of(&fs::read(site.join(name)).unwrap()),
            identity,
            "packager changed input {name}"
        );
    }
    let payload = root.join("relocated native café");
    fs::rename(output, &payload).unwrap();
    fs::remove_dir_all(environment).unwrap();
    fs::remove_dir_all(project).unwrap();
    let mut archive = Archive::open(fs::File::open(payload.join("app.glue")).unwrap()).unwrap();
    archive.verify_all().unwrap();
    assert!(
        !archive
            .manifest()
            .resources
            .keys()
            .any(|name| name.ends_with(".so") || name.ends_with(".dylib"))
    );
    let launch = archive
        .manifest()
        .distribution
        .as_ref()
        .unwrap()
        .launch
        .clone();
    let args = launch
        .args
        .iter()
        .map(|arg| {
            arg.replace("{root}", &payload.to_string_lossy())
                .replace("{archive}", &payload.join("app.glue").to_string_lossy())
        })
        .collect::<Vec<_>>();
    let result = Command::new(payload.join(&launch.executable))
        .args(&args)
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
        result.stdout, reference.stdout,
        "stock and bundled behavior differ"
    );
    if let Some(receipt) = std::env::var_os("GLUE_TEST_RECEIPT") {
        let value = serde_json::json!({"kind":"python-focused-native","application":glue_format::InputIdentity::of(&application),"target":discovery::current_target().unwrap(),"runtime":metadata,"report":report,"original_native":original_native,"source_exit":reference.status.code(),"exit":result.status.code(),"stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr),"checks":{"same_as_source":true,"input_native_unchanged":true,"project_environment_removed":true,"network_isolated":std::env::var_os("GLUE_TEST_OFFLINE").is_some(),"process_tree_trace":false}});
        fs::write(receipt, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}
