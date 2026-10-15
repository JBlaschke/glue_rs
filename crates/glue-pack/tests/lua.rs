use glue_format::{
    DiagnosticCode, InputIdentity, LuaNumber, RuntimeAbi, RuntimeDescriptor, RuntimeImplementation,
    RuntimeProvider, RuntimeVersion,
};
use glue_pack::{
    distribution::DistributionLimits,
    lua::{self, LuaProjectOptions},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "glue lua project ü {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn options(&self, minor: u16) -> LuaProjectOptions {
        let helper = self.0.join(format!("helper-{minor}"));
        fs::write(&helper, b"independent selected helper input").unwrap();
        let executable = format!("runtime/glue-lua5{minor}");
        LuaProjectOptions {
            project: self.0.join("project"),
            entry: None,
            rocks_tree: None,
            output: None,
            runtime: RuntimeDescriptor {
                implementation: RuntimeImplementation::Lua,
                version: format!("5.{minor}.{}", if minor == 4 { 9 } else { 1 }),
                target: "aarch64-apple-darwin".to_owned(),
                abi: RuntimeAbi::Lua {
                    version: RuntimeVersion {
                        major: 5,
                        minor,
                        patch: if minor == 4 { 9 } else { 1 },
                    },
                    integer_bits: 64,
                    number: LuaNumber::Float64,
                },
                provider: RuntimeProvider::Bundled,
                executable: executable.clone(),
                inputs: BTreeMap::from([(
                    executable,
                    InputIdentity::of(b"independent selected helper input"),
                )]),
                requirements: BTreeSet::new(),
            },
            helper_executable: helper,
            exclusions: Vec::new(),
            native_abis: BTreeMap::new(),
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn two_project_layouts_and_both_families_preserve_logical_sources_and_binary_assets() {
    let directory = Directory::new();
    directory.write("project/main.lua", b"local name='nested.answer'; assert(require(name)==42); assert(glue.read('app/data/value.bin')=='a\\0b')");
    directory.write("project/nested/answer.lua", b"return 42");
    directory.write("project/data/value.bin", b"a\0b");
    for minor in [4, 5] {
        let input = lua::ingest(&directory.options(minor), DistributionLimits::default()).unwrap();
        assert_eq!(input.entrypoint, "app/main.lua");
        assert_eq!(input.resources["app/data/value.bin"], b"a\0b");
        assert!(input.resources.contains_key("app/nested/answer.lua"));
        assert_eq!(input.payloads.len(), 1);
    }
    fs::remove_file(directory.0.join("project/main.lua")).unwrap();
    directory.write(
        "project/src/start.lua",
        b"assert(require('nested.answer')==42)",
    );
    let mut options = directory.options(4);
    options.entry = Some("src/start.lua".to_owned());
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap()
            .entrypoint,
        "app/src/start.lua"
    );
}

#[test]
fn selected_installed_rocks_tree_maps_source_and_native_without_building() {
    let directory = Directory::new();
    directory.write("project/main.lua", b"require('remote.module')");
    directory.write("rocks/share/lua/5.4/remote/module/init.lua", b"return 42");
    directory.write(
        "rocks/lib/lua/5.4/existing.so",
        b"existing independently built module bytes",
    );
    directory.write("rocks/share/lua/5.5/other.lua", b"error('wrong family')");
    let mut options = directory.options(4);
    options.rocks_tree = Some(directory.0.join("rocks"));
    options
        .native_abis
        .insert("app/existing.so".to_owned(), "5.4".to_owned());
    let input = lua::ingest(&options, DistributionLimits::default()).unwrap();
    assert!(input.resources.contains_key("app/remote/module/init.lua"));
    assert!(!input.resources.contains_key("app/existing.so"));
    assert_eq!(
        input.native.roots["app/existing.so"],
        "native/lua/existing.so"
    );
    assert!(input.payloads.contains_key("native/lua/existing.so"));
    assert!(
        input
            .omissions
            .contains_key("rocks/share/lua/5.5/other.lua")
    );
    assert!(
        input
            .runtime
            .requirements
            .contains("lua-native-abi:app/existing.so=5.4")
    );
}

#[test]
fn exclusions_configuration_and_ambiguity_are_reported() {
    let directory = Directory::new();
    directory.write("project/first.lua", b"return 1");
    directory.write("project/second.lua", b"return 2");
    let mut options = directory.options(4);
    let error = lua::ingest(&options, DistributionLimits::default()).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::MissingEntry);
    assert!(error.message.contains("select --entry"));
    options.entry = Some("second.lua".to_owned());
    options.exclusions = vec!["unused/**".to_owned()];
    directory.write("project/unused/cache.txt", b"unused");
    directory.write("project/glue.toml", b"entry='second.lua'");
    let input = lua::ingest(&options, DistributionLimits::default()).unwrap();
    assert!(input.omissions.contains_key("unused/cache.txt"));
    assert!(input.omissions.contains_key("glue.toml"));
    assert!(!input.resources.contains_key("app/unused/cache.txt"));
}

#[test]
fn collisions_wrong_abi_and_changed_helper_bytes_reject() {
    let directory = Directory::new();
    directory.write("project/main.lua", b"return 1");
    directory.write("project/duplicate.lua", b"return 2");
    directory.write("rocks/share/lua/5.4/duplicate.lua", b"return 3");
    let mut options = directory.options(4);
    options.rocks_tree = Some(directory.0.join("rocks"));
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidConfiguration
    );
    options.rocks_tree = None;
    directory.write("project/module.so", b"existing module");
    options
        .native_abis
        .insert("app/module.so".to_owned(), "5.5".to_owned());
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
    options.native_abis.clear();
    fs::write(&options.helper_executable, b"changed helper bytes").unwrap();
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::RuntimeAbiMismatch
    );
}

#[cfg(unix)]
#[test]
fn escaped_symlinks_are_rejected_and_internal_links_preserve_logical_name() {
    let directory = Directory::new();
    directory.write("project/main.lua", b"require('alias')");
    directory.write("project/module.lua", b"return 42");
    std::os::unix::fs::symlink(
        Path::new("module.lua"),
        directory.0.join("project/alias.lua"),
    )
    .unwrap();
    let options = directory.options(4);
    let input = lua::ingest(&options, DistributionLimits::default()).unwrap();
    assert_eq!(input.resources["app/alias.lua"], b"return 42");
    directory.write("outside.lua", b"must not ingest");
    std::os::unix::fs::symlink(
        Path::new("../outside.lua"),
        directory.0.join("project/escape.lua"),
    )
    .unwrap();
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::PathEscape
    );
}

#[test]
fn path_traversal_and_input_limits_reject_before_output() {
    let directory = Directory::new();
    directory.write("project/main.lua", b"return 42");
    let mut options = directory.options(4);
    options.entry = Some("../main.lua".to_owned());
    assert_eq!(
        lua::ingest(&options, DistributionLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::PathEscape
    );
    options.entry = None;
    let limits = DistributionLimits {
        max_input_bytes: 2,
        ..DistributionLimits::default()
    };
    assert_eq!(
        lua::ingest(&options, limits).unwrap_err().code,
        DiagnosticCode::ResourceLimit
    );
}
