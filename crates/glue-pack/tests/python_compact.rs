#![cfg(feature = "python")]
use glue_format::{Archive, RuntimeProvider};
use glue_pack::{
    distribution,
    python::{
        compact::{self, CompactBuildOptions},
        discovery::{self, DiscoveryOptions},
        inventory::{InventoryOptions, PythonEntry},
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
fn copy_input(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if ["site-packages", "__pycache__"].contains(&entry.file_name().to_string_lossy().as_ref())
        {
            continue;
        }
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(fs::read_link(entry.path()).unwrap(), target).unwrap();
        } else if entry.file_type().unwrap().is_dir() {
            copy_input(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
#[ignore = "requires a supplied runtime in GLUE_TEST_PYTHON; executes the relocated native runtime"]
fn bundled_runtime_and_sources_launch_with_original_inputs_removed() {
    let python =
        PathBuf::from(std::env::var_os("GLUE_TEST_PYTHON").expect("supply GLUE_TEST_PYTHON"));
    let metadata = discovery::probe(&python, Duration::from_secs(15)).unwrap();
    let root = std::env::temp_dir().join(format!("glue-python-compact-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(&root).unwrap();
    let supplied = root.join("supplied runtime");
    copy_input(&metadata.prefix, &supplied);
    let executable = if !metadata.framework.is_empty() {
        supplied.join("Resources/Python.app/Contents/MacOS/Python")
    } else {
        supplied.join(
            python
                .canonicalize()
                .unwrap()
                .strip_prefix(&metadata.prefix)
                .unwrap(),
        )
    };
    if !metadata.framework.is_empty() {
        assert!(
            std::env::var_os("GLUE_TEST_NORMALIZE").is_some(),
            "framework test input preparation requires explicit normalization"
        );
        let original_image = metadata.prefix.join("Python");
        let status = Command::new("/usr/bin/install_name_tool")
            .arg("-change")
            .arg(&original_image)
            .arg("@executable_path/../../../../Python")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        eprintln!(
            "independent framework fixture preparation: rewrote {} to @executable_path/../../../../Python in controlled copied real app executable and ad-hoc signed it; product reports its own later transformations",
            original_image.display()
        );
    }
    let project = root.join("project");
    let environment = root.join("environment");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(environment.join("bin")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&executable, environment.join("bin/python")).unwrap();
    fs::write(
        environment.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\n",
            supplied.display()
        ),
    )
    .unwrap();
    let version = format!("{}.{}", metadata.version[0], metadata.version[1]);
    let site = environment.join(format!("lib/python{version}/site-packages"));
    fs::create_dir_all(&site).unwrap();
    fs::write(project.join("main.py"),r#"import codecs, importlib, importlib.util, json, math, ssl, sys
assert codecs.lookup('cp437')
assert math.sqrt(81) == 9
assert ssl.OPENSSL_VERSION
native = next((name for name in ['_dbm','_ctypes','_decimal','_ssl'] if (spec := importlib.util.find_spec(name)) and spec.origin and spec.origin.endswith(('.so','.dylib'))), None)
assert native, 'no native stdlib smoke candidate'
assert importlib.import_module(native).__file__
print(json.dumps({'status':'python-runtime-ok','version':list(sys.version_info[:3]),'native':native,'argv':sys.argv[1:]}))
"#).unwrap();
    let options = CompactBuildOptions {
        discovery: DiscoveryOptions {
            environment: environment.clone(),
            runtime: std::env::var_os("GLUE_TEST_PYTHON_ARCHIVE").map(PathBuf::from),
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
        app_id: "python-runtime".into(),
    };
    let output = root.join("built");
    let context = std::collections::BTreeMap::from([("glue.cli.language".into(), "python".into())]);
    let report =
        compact::build_with_options(&options, Path::new("/usr/bin/true"), &output, &context)
            .unwrap();
    let lock: glue_format::BuildLock =
        serde_json::from_slice(&fs::read(output.join("glue.lock.json")).unwrap()).unwrap();
    assert_eq!(lock.options["glue.cli.language"], "python");
    assert_eq!(report.runtime.provider, RuntimeProvider::Bundled);
    let mut wrong_provider = report.runtime.clone();
    wrong_provider.provider = RuntimeProvider::Host;
    let wrong_context = std::collections::BTreeMap::from([(
        "glue.expected-runtime".into(),
        serde_json::to_string(&wrong_provider).unwrap(),
    )]);
    let wrong_output = root.join("wrong-provider");
    assert_eq!(
        compact::build_with_options(
            &options,
            Path::new("/usr/bin/true"),
            &wrong_output,
            &wrong_context
        )
        .unwrap_err()
        .code,
        glue_format::DiagnosticCode::PayloadIntegrity
    );
    assert!(!wrong_output.exists());
    assert_eq!(
        report
            .payloads
            .keys()
            .filter(|path| path.ends_with(".py"))
            .count(),
        1
    );
    let relocated = root.join("relocated café distribution");
    fs::rename(&output, &relocated).unwrap();
    fs::remove_dir_all(supplied).unwrap();
    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(environment).unwrap();
    let mut archive = Archive::open(fs::File::open(relocated.join("app.glue")).unwrap()).unwrap();
    archive.verify_all().unwrap();
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
            arg.replace("{root}", &relocated.to_string_lossy())
                .replace("{archive}", &relocated.join("app.glue").to_string_lossy())
        })
        .collect::<Vec<_>>();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in distribution::collect_tree(&relocated, None, 100_000)
            .unwrap()
            .values()
        {
            let mode = fs::metadata(path).unwrap().permissions().mode();
            fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o222)).unwrap();
        }
    }
    let executable = relocated.join(&launch.executable);
    let result = Command::new(&executable)
        .args(&args)
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
    let observed: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(observed["status"], "python-runtime-ok");
    assert_eq!(observed["version"], serde_json::json!(metadata.version));
    assert_eq!(observed["argv"], serde_json::json!(["argument café"]));
    if let Some(receipt) = std::env::var_os("GLUE_TEST_RECEIPT") {
        let receipt = PathBuf::from(receipt);
        let value = serde_json::json!({"kind":"python-focused-provider","target":discovery::current_target().unwrap(),"runtime":metadata,"report":report,"command":{"executable":executable,"argv":args,"application_arguments":["argument café"]},"exit":result.status.code(),"stdout":observed,"stderr":String::from_utf8_lossy(&result.stderr),"checks":{"controlled_input_prefix_removed":true,"relocated_nonascii_path":true,"readonly_files":true,"empty_path":true,"unusable_home_temp":true,"network_isolated":std::env::var_os("GLUE_TEST_OFFLINE").is_some(),"syscall_trace":false},"limitations":["Focused provider receipt does not replace V02/R02 process-tree trace/signing receipts"]});
        fs::write(receipt, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}
