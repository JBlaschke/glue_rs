use glue_format::{
    Architecture, Compression, Manifest, OperatingSystem, Provisioning, ResourceSpec, RuntimeAbi,
    TargetAbi, digest, write_archive,
};
use glue_runtime_lua::{helper, profile};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
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
            "glue helper ü {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn archive(directory: &Directory, source: &[u8], wrong_family: bool) -> PathBuf {
    let mut manifest = Manifest::from_json(include_bytes!(
        "../../../fixtures/lua-linked/manifest.macos-arm64.json"
    ))
    .unwrap();
    let target = manifest.targets.values_mut().next().unwrap();
    target.arch = if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else {
        Architecture::X86_64
    };
    target.minimum_os_version = "1.0".to_owned();
    target.page_sizes = [4096, 16384, 65536].into_iter().collect();
    if cfg!(target_os = "linux") {
        target.os = OperatingSystem::Linux;
        target.abi = TargetAbi::Glibc {
            minimum_version: "2.17".to_owned(),
        };
    }
    let runtime = manifest.runtimes.values_mut().next().unwrap();
    let descriptor = helper::compiled_descriptor();
    runtime.build_id = descriptor.build_id;
    runtime.abi = RuntimeAbi::Lua {
        version: descriptor.version,
        integer_bits: 64,
        number: descriptor.number,
    };
    runtime.provisioning = Provisioning::Linked {
        provider: glue_format::BundledProvider::LuaSource,
        source: descriptor.source,
    };
    if wrong_family {
        let RuntimeAbi::Lua { version, .. } = &mut runtime.abi else {
            unreachable!()
        };
        version.minor = if version.minor == 4 { 5 } else { 4 };
        version.patch = if version.minor == 4 { 9 } else { 1 };
        runtime.build_id = format!(
            "glue-lua5{}-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64",
            version.minor
        );
        let Provisioning::Linked { source, .. } = &mut runtime.provisioning else {
            unreachable!()
        };
        source.release = format!("5.{}.{}", version.minor, version.patch);
        source.variant = format!("lua5{}-static-int64-float64", version.minor);
    }
    let contents = BTreeMap::from([
        ("app/main.lua".to_owned(), source.to_vec()),
        (
            "app/lib/answer.lua".to_owned(),
            include_bytes!("../../../fixtures/lua-linked/input/app/lib/answer.lua").to_vec(),
        ),
        (
            "app/lib/number.lua".to_owned(),
            include_bytes!("../../../fixtures/lua-linked/input/app/lib/number.lua").to_vec(),
        ),
        (
            "assets/message.txt".to_owned(),
            include_bytes!("../../../fixtures/lua-linked/input/assets/message.txt").to_vec(),
        ),
    ]);
    manifest.resources = contents
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression: Compression::Stored,
                },
            )
        })
        .collect();
    let path = directory.0.join("application with spaces.glue");
    write_archive(fs::File::create(&path).unwrap(), &manifest, &contents).unwrap();
    path
}

#[cfg(not(feature = "linux-native"))]
#[test]
fn helper_descriptor_and_explicit_discovery_match_exact_selected_runtime() {
    let expected = helper::compiled_descriptor();
    let descriptor = helper::query(std::path::Path::new(HELPER)).unwrap();
    assert_eq!(descriptor, expected);
    descriptor
        .validate(descriptor.family, &descriptor.target)
        .unwrap();
    let directory = Directory::new();
    let installed = directory.0.join(expected.family.executable_name());
    fs::copy(HELPER, installed).unwrap();
    let selected =
        helper::discover(expected.family, &expected.target, &[directory.0.clone()]).unwrap();
    assert_eq!(selected.sha256, digest(&fs::read(HELPER).unwrap()));
    assert_eq!(selected.size, fs::metadata(HELPER).unwrap().len());
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
#[test]
fn helper_runs_existing_source_resource_fixture_with_protected_errors() {
    let directory = Directory::new();
    let path = archive(
        &directory,
        include_bytes!("../../../fixtures/lua-linked/input/app/main.lua"),
        false,
    );
    let output = Command::new(HELPER)
        .arg("run")
        .arg(&path)
        .current_dir("/")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(profile::LUA_VERSION), "{stdout}");
    let path = archive(&directory, b"assert(math.maxinteger == 9223372036854775807); assert(string.packsize('n') == 8); error('protected helper failure')", false);
    let output = Command::new(HELPER).arg("run").arg(path).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("protected helper failure"), "{stderr}");
    assert!(stderr.contains("glue://"), "{stderr}");
}

#[test]
fn helper_rejects_other_family_before_executing_application() {
    let directory = Directory::new();
    let path = archive(&directory, b"print('must not execute')", true);
    let output = Command::new(HELPER).arg("run").arg(path).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime build ID"));
}

#[test]
fn helper_rejects_unrecognized_invocations() {
    for arguments in [
        vec![],
        vec!["--version"],
        vec!["run"],
        vec!["run", "x", "ignored"],
    ] {
        assert_eq!(
            Command::new(HELPER)
                .args(arguments)
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
    }
}

#[cfg(not(feature = "linux-native"))]
#[test]
fn compact_helper_validates_shared_runtime_descriptor_before_entry() {
    use glue_format::{
        DeliveryMode, DistributionSpec, InputIdentity, NativeInventory, PayloadKind, PayloadRecord,
    };
    let directory = Directory::new();
    let legacy = archive(
        &directory,
        b"assert(math.maxinteger == 9223372036854775807); assert(arg[0]:find('glue://',1,true)); assert(arg[1]=='value with spaces'); assert((...)==arg[1]); assert(type(io.open)=='function'); print(_VERSION)",
        false,
    );
    let mut source_archive = glue_format::Archive::open(fs::File::open(&legacy).unwrap()).unwrap();
    let mut manifest = source_archive.manifest().clone();
    let contents: BTreeMap<_, _> = manifest
        .resources
        .keys()
        .map(|path| (path.clone(), source_archive.read_resource(path).unwrap()))
        .collect();
    let helper_bytes = fs::read(HELPER).unwrap();
    let descriptor = helper::compiled_descriptor();
    let executable = format!("runtime/{}", descriptor.family.executable_name());
    manifest.schema_version = 1;
    manifest.entrypoint = "app/main.lua".to_owned();
    manifest.targets.clear();
    manifest.runtimes.clear();
    manifest.components.clear();
    manifest.distribution = Some(DistributionSpec {
        delivery: DeliveryMode::Compact,
        runtime: descriptor
            .runtime_descriptor(executable.clone(), InputIdentity::of(&helper_bytes)),
        payloads: BTreeMap::from([(
            executable.clone(),
            PayloadRecord {
                size: helper_bytes.len() as u64,
                sha256: digest(&helper_bytes),
                mode: 0o755,
                kind: PayloadKind::File,
            },
        )]),
        native: NativeInventory::default(),
        launch: descriptor.launch_spec(executable),
    });
    let path = directory.0.join("compact.glue");
    write_archive(fs::File::create(&path).unwrap(), &manifest, &contents).unwrap();
    let output = Command::new(HELPER)
        .arg("run")
        .arg(&path)
        .args(["--", "value with spaces"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime = &mut manifest.distribution.as_mut().unwrap().runtime;
    runtime.version = "5.4.8".to_owned();
    let RuntimeAbi::Lua { version, .. } = &mut runtime.abi else {
        unreachable!()
    };
    version.major = 5;
    version.minor = 4;
    version.patch = 8;
    write_archive(fs::File::create(&path).unwrap(), &manifest, &contents).unwrap();
    let output = Command::new(HELPER).arg("run").arg(path).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime ABI/version/target"));
}

#[test]
fn compact_helper_preserves_application_exit_status() {
    use glue_format::{
        DeliveryMode, DistributionSpec, InputIdentity, NativeInventory, PayloadKind, PayloadRecord,
    };
    let directory = Directory::new();
    let path = archive(&directory, b"os.exit(7)", false);
    let mut archive = glue_format::Archive::open(fs::File::open(&path).unwrap()).unwrap();
    let mut manifest = archive.manifest().clone();
    let contents: BTreeMap<_, _> = manifest
        .resources
        .keys()
        .map(|path| (path.clone(), archive.read_resource(path).unwrap()))
        .collect();
    let bytes = fs::read(HELPER).unwrap();
    let descriptor = helper::compiled_descriptor();
    let executable = format!("runtime/{}", descriptor.family.executable_name());
    manifest.schema_version = 1;
    manifest.entrypoint = "app/main.lua".to_owned();
    manifest.targets.clear();
    manifest.runtimes.clear();
    manifest.components.clear();
    manifest.distribution = Some(DistributionSpec {
        delivery: DeliveryMode::Compact,
        runtime: descriptor.runtime_descriptor(executable.clone(), InputIdentity::of(&bytes)),
        payloads: BTreeMap::from([(
            executable.clone(),
            PayloadRecord {
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                mode: 0o755,
                kind: PayloadKind::File,
            },
        )]),
        native: NativeInventory::default(),
        launch: descriptor.launch_spec(executable),
    });
    write_archive(fs::File::create(&path).unwrap(), &manifest, &contents).unwrap();
    assert_eq!(
        Command::new(HELPER)
            .arg("run")
            .arg(path)
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
}
