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
        b"assert(math.maxinteger == 9223372036854775807); print(_VERSION)",
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
    let output = Command::new(HELPER).arg("run").arg(&path).output().unwrap();
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

#[cfg(unix)]
fn independent_query_program(directory: &Directory, name: &str, source: &str) -> PathBuf {
    let input = directory.0.join(format!("{name}.c"));
    let executable = directory.0.join(name);
    fs::write(&input, source).unwrap();
    let output = Command::new("cc")
        .args([
            "-O2",
            "-std=c11",
            "-D_DARWIN_C_SOURCE",
            "-D_DEFAULT_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg(&input)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

#[cfg(unix)]
#[test]
fn descriptor_query_deadline_kills_and_reaps_real_programs_with_open_or_closed_stdout() {
    use std::time::{Duration, Instant};
    let directory = Directory::new();
    let descriptor = serde_json::to_string(&helper::compiled_descriptor()).unwrap();
    let quoted = serde_json::to_string(&descriptor).unwrap();
    let source = format!(
        r#"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv) {{
    char path[4096];
    FILE *file;
    if (argc==3 && strcmp(argv[1],"--check-pid")==0) {{
        long pid=strtol(argv[2],NULL,10);
        if (pid<=0) return 8;
        return kill((pid_t)pid,0)==-1 && errno==ESRCH ? 0 : 1;
    }}
    alarm(20);
    if (snprintf(path,sizeof(path),"%s.pid",argv[0]) >= (int)sizeof(path)) return 3;
    file=fopen(path,"w");
    if (!file) return 4;
    fprintf(file,"%ld",(long)getpid());
    if (fclose(file)) return 5;
    if (strstr(argv[0],"closed-stdout")) {{
        fputs({quoted},stdout);
        fclose(stdout);
    }} else {{
        fputs("{{",stdout);
        fflush(stdout);
    }}
    for (;;) pause();
}}
"#
    );
    let opened = independent_query_program(&directory, "open-stdout", &source);
    let closed = directory.0.join("closed-stdout");
    fs::copy(&opened, &closed).unwrap();
    std::thread::scope(|scope| {
        let probes:Vec<_>=[opened,closed].into_iter().map(|path| scope.spawn(move || {
            let started=Instant::now();
            let error=helper::query(&path).unwrap_err();
            assert!(matches!(&error,helper::HelperError::Invalid(message) if message.contains("timed out after 5s")),"{error}");
            assert!(started.elapsed()>=Duration::from_millis(4500));
            assert!(started.elapsed()<Duration::from_secs(10));
            let pid=fs::read_to_string(path.with_extension("pid")).unwrap();
            let status=Command::new(&path).args(["--check-pid",pid.trim()]).output().unwrap();
            assert!(status.status.success(),"timed-out helper {pid} was not killed/reaped");
        })).collect();
        for probe in probes {
            probe.join().unwrap();
        }
    });
}

#[cfg(unix)]
#[test]
fn descriptor_query_preserves_output_bound_and_other_spawn_errors() {
    use std::os::unix::fs::PermissionsExt;
    let directory = Directory::new();
    let noisy = independent_query_program(
        &directory,
        "noisy",
        r#"
#include <stdio.h>
int main(void) { for(int n=0;n<65537;n++) putchar('x'); return 0; }
"#,
    );
    assert!(
        matches!(helper::query(&noisy),Err(helper::HelperError::Invalid(message)) if message.contains("64 KiB"))
    );
    let missing = directory.0.join("missing");
    assert!(
        matches!(helper::query(&missing),Err(helper::HelperError::Io(error)) if error.kind()==std::io::ErrorKind::NotFound)
    );
    fs::set_permissions(&noisy, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        matches!(helper::query(&noisy),Err(helper::HelperError::Io(error)) if error.kind()==std::io::ErrorKind::PermissionDenied)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn descriptor_query_retries_only_transient_executable_busy_and_bounds_persistent_busy() {
    use std::{
        fs::OpenOptions,
        time::{Duration, Instant},
    };
    let directory = Directory::new();
    let descriptor = helper::compiled_descriptor();
    let quoted = serde_json::to_string(&serde_json::to_string(&descriptor).unwrap()).unwrap();
    let executable = independent_query_program(
        &directory,
        "busy-descriptor",
        &format!("#include <stdio.h>\nint main(void){{fputs({quoted},stdout);return 0;}}\n"),
    );
    let writer = OpenOptions::new().write(true).open(&executable).unwrap();
    let error = Command::new(&executable).spawn().unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETXTBSY));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        drop(writer);
    });
    let result = helper::query(&executable);
    release.join().unwrap();
    assert_eq!(result.unwrap(), descriptor);
    let _writer = OpenOptions::new().write(true).open(&executable).unwrap();
    let started = Instant::now();
    assert!(
        matches!(helper::query(&executable),Err(helper::HelperError::Io(error)) if error.raw_os_error()==Some(libc::ETXTBSY))
    );
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(2));
}
