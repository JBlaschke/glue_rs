//! The fixture compiler runs before packaging. The packager consumes its bytes.
#![cfg(unix)]
use glue_format::{DiagnosticCode, InputIdentity};
use glue_pack::{
    distribution::DistributionLimits,
    lua::{self, LuaProjectOptions},
};
use glue_runtime_lua::helper;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "lua54")]
const HELPER: &str = env!("CARGO_BIN_EXE_glue-lua54");
#[cfg(feature = "lua55")]
const HELPER: &str = env!("CARGO_BIN_EXE_glue-lua55");

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "glue native ü {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile(project: &Path) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mvp/lua-native");
    let mut dependency = Command::new("cc");
    dependency.args(["-fPIC", "-pthread"]);
    if cfg!(target_os = "macos") {
        dependency.args(["-dynamiclib", "-Wl,-install_name,@rpath/libsecondary.dylib"]);
    } else {
        dependency.args(["-shared", "-Wl,-soname,libsecondary.so"]);
    }
    dependency
        .arg(fixture.join("secondary.c"))
        .arg("-o")
        .arg(project.join(if cfg!(target_os = "macos") {
            "libsecondary.dylib"
        } else {
            "libsecondary.so"
        }));
    let output = dependency.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut module = Command::new("cc");
    module
        .arg("-fPIC")
        .arg("-I")
        .arg(env!("GLUE_LUA_INCLUDE_PATH"));
    if cfg!(target_os = "macos") {
        module.args([
            "-bundle",
            "-undefined",
            "dynamic_lookup",
            "-Wl,-rpath,@loader_path",
        ]);
    } else {
        module.args(["-shared", "-Wl,-rpath,$ORIGIN"]);
    }
    module
        .arg(fixture.join("module.c"))
        .arg("-L")
        .arg(project)
        .arg("-lsecondary")
        .arg("-o")
        .arg(project.join("module.so"));
    let output = module.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn options(directory: &Directory) -> LuaProjectOptions {
    let project = directory.0.join("original inputs");
    fs::create_dir(&project).unwrap();
    compile(&project);
    fs::write(
        project.join("main.lua"),
        include_bytes!("../../../fixtures/mvp/lua-native/main.lua"),
    )
    .unwrap();
    for alias in ["failed.so", "missing.so", "mismatched.so"] {
        std::os::unix::fs::symlink("module.so", project.join(alias)).unwrap();
    }
    let descriptor = helper::compiled_descriptor();
    let executable = format!("runtime/{}", descriptor.family.executable_name());
    let family = format!("5.{}", descriptor.version.minor);
    LuaProjectOptions {
        project,
        entry: None,
        rocks_tree: None,
        output: None,
        runtime: descriptor
            .runtime_descriptor(executable, InputIdentity::of(&fs::read(HELPER).unwrap())),
        helper_executable: PathBuf::from(HELPER),
        exclusions: Vec::new(),
        native_abis: ["module.so", "failed.so", "missing.so", "mismatched.so"]
            .into_iter()
            .map(|name| (format!("app/{name}"), family.clone()))
            .collect(),
        native_search: Vec::new(),
        normalize_native_paths: false,
    }
}

fn run(root: &Path) -> std::process::Output {
    let helper = root
        .join("runtime")
        .join(helper::compiled_descriptor().family.executable_name());
    Command::new(helper)
        .arg("run")
        .arg(root.join("app.glue"))
        .current_dir("/")
        .env_clear()
        .env("PATH", "/no-language-tools")
        .env("HOME", "/unusable-glue-home")
        .env("TMPDIR", "/unusable-glue-temp")
        .output()
        .unwrap()
}

#[test]
fn prebuilt_module_secondary_tls_callbacks_errors_and_aliases_work_after_relocation() {
    let directory = Directory::new();
    let options = options(&directory);
    let before = InputIdentity::of(&fs::read(options.project.join("module.so")).unwrap());
    let built = directory.0.join("build output");
    let report = lua::build(
        &options,
        Path::new(HELPER),
        &built,
        DistributionLimits::default(),
    )
    .unwrap();
    assert_eq!(
        before,
        InputIdentity::of(&fs::read(options.project.join("module.so")).unwrap())
    );
    let deployed = report.native.roots.get("app/module.so").unwrap();
    assert_eq!(report.payloads[deployed].sha256, before.sha256);
    assert!(!report.native.roots.contains_key("app/libsecondary.so"));
    assert!(report.native.features.contains("tls"));
    let relocated = directory.0.join("relocated payload ü");
    fs::rename(&built, &relocated).unwrap();
    fs::remove_dir_all(&options.project).unwrap();
    let output = run(&relocated);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("native module/secondary/TLS/callback/errors passed")
    );
    // A fresh process must reject tampering before calling any native initializer.
    let mut corrupt = fs::read(relocated.join(deployed)).unwrap();
    corrupt[0] ^= 1;
    fs::write(relocated.join(deployed), corrupt).unwrap();
    let output = run(&relocated);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("integrity verification"));
}

#[test]
fn native_abi_declaration_and_missing_secondary_fail_without_publication_or_fallback() {
    let directory = Directory::new();
    let mut options = options(&directory);
    let output = directory.0.join("must remain absent");
    options.native_abis.insert(
        "app/module.so".to_owned(),
        if helper::compiled_descriptor().version.minor == 4 {
            "5.5"
        } else {
            "5.4"
        }
        .to_owned(),
    );
    assert_eq!(
        lua::build(
            &options,
            Path::new(HELPER),
            &output,
            DistributionLimits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
    assert!(!output.exists());
    options.native_abis.clear();
    assert_eq!(
        lua::build(
            &options,
            Path::new(HELPER),
            &output,
            DistributionLimits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
    assert!(!output.exists());
    let family = format!("5.{}", helper::compiled_descriptor().version.minor);
    options.native_abis = BTreeMap::from([
        ("app/module.so".to_owned(), family.clone()),
        ("app/failed.so".to_owned(), family.clone()),
        ("app/missing.so".to_owned(), family.clone()),
        ("app/mismatched.so".to_owned(), family),
    ]);
    lua::build(
        &options,
        Path::new(HELPER),
        &output,
        DistributionLimits::default(),
    )
    .unwrap();
    let secondary = output
        .join("native/lua")
        .join(if cfg!(target_os = "macos") {
            "libsecondary.dylib"
        } else {
            "libsecondary.so"
        });
    fs::remove_file(secondary).unwrap();
    let result = run(&output);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("native payload"));
}
