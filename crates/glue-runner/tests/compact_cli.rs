use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
fn glue() -> Command {
    Command::new(env!("CARGO_BIN_EXE_glue"))
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "glue-cli-{}-{}",
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
#[test]
fn invalid_mode_unknown_config_and_duplicate_options_fail_without_publication() {
    let t = Temp::new();
    let out = t.0.join("absent");
    for args in [
        vec!["--delivery", "memory"],
        vec!["--lua", "5.4", "--lua", "5.5"],
        vec!["--unknown"],
    ] {
        let result = glue()
            .args(["build", "lua"])
            .arg(&t.0)
            .arg("--output")
            .arg(&out)
            .args(args)
            .arg("--json")
            .output()
            .unwrap();
        assert!(!result.status.success());
        let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert!(error["code"].is_string());
        assert!(!out.exists());
    }
    fs::write(t.0.join("glue.toml"), "misspelled = 1\n").unwrap();
    let result = glue()
        .args(["build", "lua"])
        .arg(&t.0)
        .arg("--output")
        .arg(&out)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stderr).unwrap()["code"],
        "invalid_configuration"
    );
}
#[test]
fn relocated_lua_cli_forwards_io_argv_and_exit_and_checks_payloads() {
    let helper_dir = std::env::var_os("GLUE_LUA_TEST_HELPER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_BIN_EXE_glue"))
                .parent()
                .unwrap()
                .to_owned()
        });
    if !helper_dir.join("glue-lua54").is_file() {
        assert!(
            std::env::var_os("GLUE_REQUIRE_COMPACT_CLI").is_none(),
            "required Lua helper missing"
        );
        eprintln!(
            "compact CLI runtime execution unperformed: build glue-lua54 or set GLUE_LUA_TEST_HELPER_DIR"
        );
        return;
    }
    let t = Temp::new();
    let project = t.0.join("source project");
    fs::create_dir(&project).unwrap();
    fs::write(
        project.join("main.lua"),
        "io.write(arg[1] .. '|' .. io.read('*l')); io.stderr:write('stderr'); os.exit(7)\n",
    )
    .unwrap();
    fs::write(
        project.join("glue.toml"),
        "entry = 'wrong.lua'\n[lua]\nversion = '5.5'\n",
    )
    .unwrap();
    let out = t.0.join("build-output");
    let result = glue()
        .args(["build", "lua"])
        .arg(&project)
        .args(["--lua", "5.4", "--entry", "main.lua", "--helper-dir"])
        .arg(&helper_dir)
        .arg("--output")
        .arg(&out)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["runtime"]["version"], "5.4.9");
    fs::remove_dir_all(&project).unwrap();
    let relocated = t.0.join("relocated ü {archive} directory");
    fs::rename(&out, &relocated).unwrap();
    for p in glue_pack::distribution::collect_tree(&relocated, None, 100)
        .unwrap()
        .values()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(p).unwrap().permissions().mode() & !0o222;
            fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    let mut app = Command::new(relocated.join("glue"))
        .arg("run")
        .arg(relocated.join("app.glue"))
        .args(["--", "literal $(no-shell) ü"])
        .env_clear()
        .env("PATH", "/no-tools")
        .env("HOME", "/no-home")
        .env("TMPDIR", "/no-temp")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    app.stdin
        .take()
        .unwrap()
        .write_all(b"streamed-input\n")
        .unwrap();
    let result = app.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(7));
    assert_eq!(
        result.stdout,
        "literal $(no-shell) ü|streamed-input".as_bytes()
    );
    assert_eq!(result.stderr, b"stderr");
    let doctor = glue()
        .arg("doctor")
        .arg(relocated.join("app.glue"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&doctor.stdout).unwrap()["application_executed"],
        false
    );
    fs::remove_file(relocated.join("runtime/glue-lua54")).unwrap();
    let result = glue()
        .arg("run")
        .arg(relocated.join("app.glue"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stderr).unwrap()["code"],
        "missing_dependency"
    );
    assert!(!relocated.join("runtime/glue-lua54").exists());
}

#[cfg(unix)]
#[test]
fn compact_launcher_preserves_sigint_and_sigterm() {
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
    };
    let helpers = std::env::var_os("GLUE_LUA_TEST_HELPER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_BIN_EXE_glue"))
                .parent()
                .unwrap()
                .to_owned()
        });
    if !helpers.join("glue-lua54").is_file() {
        assert!(
            std::env::var_os("GLUE_REQUIRE_COMPACT_CLI").is_none(),
            "required Lua helper missing"
        );
        return;
    }
    let t = Temp::new();
    let project = t.0.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(
        project.join("main.lua"),
        "io.write('ready\\n');io.flush();while true do end\n",
    )
    .unwrap();
    let out = t.0.join("dist");
    let result = glue()
        .args(["build", "lua"])
        .arg(&project)
        .arg("--helper-dir")
        .arg(helpers)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (signal, number) in [("-INT", 2), ("-TERM", 15)] {
        let mut child = Command::new(out.join("glue"))
            .arg("run")
            .arg(out.join("app.glue"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        assert!(
            Command::new("/bin/kill")
                .arg(signal)
                .arg(child.id().to_string())
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(child.wait().unwrap().signal(), Some(number));
    }
}

#[test]
fn recorded_rebuild_reuses_runtime_and_rejects_runtime_lock_changes_before_publish() {
    let helpers = std::env::var_os("GLUE_LUA_TEST_HELPER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_BIN_EXE_glue"))
                .parent()
                .unwrap()
                .to_owned()
        });
    if !helpers.join("glue-lua54").is_file() {
        assert!(std::env::var_os("GLUE_REQUIRE_COMPACT_CLI").is_none());
        return;
    }
    let t = Temp::new();
    let project = t.0.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("main.lua"), "print('rebuild')\n").unwrap();
    let original = t.0.join("original");
    let result = glue()
        .args(["build", "lua"])
        .arg(&project)
        .arg("--helper-dir")
        .arg(helpers)
        .arg("--output")
        .arg(&original)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rebuilt = t.0.join("rebuilt");
    let result = glue()
        .arg("rebuild")
        .arg(original.join("glue.lock.json"))
        .arg("--output")
        .arg(&rebuilt)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(original.join("app.glue")).unwrap(),
        fs::read(rebuilt.join("app.glue")).unwrap()
    );
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(original.join("glue.lock.json")).unwrap()).unwrap();
    lock["runtime"]["version"] = "5.4.8".into();
    let invalid = t.0.join("invalid.lock.json");
    fs::write(&invalid, serde_json::to_vec(&lock).unwrap()).unwrap();
    let absent = t.0.join("absent");
    let result = glue()
        .arg("rebuild")
        .arg(&invalid)
        .arg("--output")
        .arg(&absent)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stderr).unwrap()["code"],
        "payload_integrity"
    );
    assert!(!absent.exists());
}
