use glue_format::{Archive, Manifest};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let base = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        loop {
            let path = base.join(format!(
                "glue CLI tests ü {} {}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory {path:?}: {error}"),
            }
        }
    }

    fn run(&self, args: &[&OsStr]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_glue"))
            .args(args)
            .current_dir(&self.0)
            .stdin(Stdio::null())
            .output()
            .expect("execute glue CLI")
    }

    fn build_output(&self, manifest: &Path, output: &Path, standalone: bool) -> Output {
        let root = fixture().join("input");
        let mut args = vec![
            arg("build"),
            arg("--manifest"),
            manifest.as_os_str(),
            arg("--root"),
            root.as_os_str(),
            arg("--output"),
            output.as_os_str(),
        ];
        if standalone {
            args.push(arg("--standalone"));
        }
        self.run(&args)
    }

    fn build(&self, name: &str) -> PathBuf {
        let output = self.0.join(name);
        let result = self.build_output(&fixture().join("manifest.json"), &output, false);
        assert_status(&result, 0);
        assert!(output.is_file());
        output
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        // Every test owns only the unique directory it created above.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn arg(text: &str) -> &OsStr {
    OsStr::new(text)
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/resources")
        .canonicalize()
        .expect("resource fixture exists")
}

fn diagnostic(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_status(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "glue output: {}",
        diagnostic(output)
    );
}

fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                result.insert(relative, None);
                visit(root, &path, result);
            } else {
                assert!(kind.is_file(), "unexpected test directory entry {path:?}");
                result.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn builds_are_deterministic_and_relocated_archives_remain_readable() {
    let temp = TestDir::new();
    let first = temp.build("first archive.glue");
    let second = temp.build("second archive.glue");
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let relocated_directory = temp.0.join("relocated archive é");
    fs::create_dir(&relocated_directory).unwrap();
    let relocated = relocated_directory.join("renamed bundle.glue");
    fs::rename(&first, &relocated).unwrap();

    let inspect = temp.run(&[arg("inspect"), relocated.as_os_str()]);
    assert_status(&inspect, 0);
    assert!(diagnostic(&inspect).contains("resource-fixture"));

    let json = temp.run(&[arg("inspect"), relocated.as_os_str(), arg("--json")]);
    assert_status(&json, 0);
    let actual = Manifest::from_json(&json.stdout).expect("inspect emits only valid manifest JSON");
    let expected =
        Manifest::from_json(&fs::read(fixture().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(actual, expected);

    let verify = temp.run(&[arg("verify"), relocated.as_os_str()]);
    assert_status(&verify, 0);
    for resource in ["app/main.lua", "assets/message.txt"] {
        let cat = temp.run(&[arg("cat"), relocated.as_os_str(), arg(resource)]);
        assert_status(&cat, 0);
        assert_eq!(
            cat.stdout,
            fs::read(fixture().join("input").join(resource)).unwrap()
        );
        assert!(cat.stderr.is_empty());
    }
}

#[test]
fn explain_size_reports_payload_totals_and_container_overhead() {
    let temp = TestDir::new();
    let path = temp.build("sizes.glue");
    let archive = Archive::open(File::open(&path).unwrap()).unwrap();
    let compressed: u64 = archive
        .entries()
        .values()
        .map(|entry| entry.compressed_size)
        .sum();
    let uncompressed: u64 = archive.entries().values().map(|entry| entry.size).sum();
    let overhead = fs::metadata(&path).unwrap().len() - compressed;
    let result = temp.run(&[arg("explain-size"), path.as_os_str()]);
    assert_status(&result, 0);
    let text = String::from_utf8(result.stdout).unwrap();
    for (label, expected) in [
        ("compressed", compressed),
        ("uncompressed", uncompressed),
        ("overhead", overhead),
    ] {
        let actual = text
            .lines()
            .find_map(|line| {
                let words: Vec<_> = line
                    .split_whitespace()
                    .map(|word| {
                        word.trim_matches(|character: char| !character.is_ascii_alphanumeric())
                    })
                    .collect();
                words.windows(2).find_map(|pair| {
                    if pair[0].eq_ignore_ascii_case(label) {
                        pair[1].parse::<u64>().ok()
                    } else if pair[1].eq_ignore_ascii_case(label) {
                        pair[0].parse::<u64>().ok()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| panic!("missing {label} total: {text}"));
        assert_eq!(actual, expected, "incorrect {label} total: {text}");
    }
}

#[test]
fn build_preserves_existing_outputs_and_rejects_incorrect_declared_hashes() {
    let temp = TestDir::new();
    let existing = temp.0.join("existing.glue");
    fs::write(&existing, b"keep this existing output").unwrap();
    let result = temp.build_output(&fixture().join("manifest.json"), &existing, false);
    assert_status(&result, 1);
    assert!(!result.stderr.is_empty());
    assert_eq!(fs::read(&existing).unwrap(), b"keep this existing output");

    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture().join("manifest.json")).unwrap()).unwrap();
    manifest["resources"]["assets/message.txt"]["sha256"] = "0".repeat(64).into();
    let changed = temp.0.join("incorrect manifest.json");
    fs::write(&changed, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let rejected = temp.0.join("rejected.glue");
    let result = temp.build_output(&changed, &rejected, false);
    assert_status(&result, 1);
    assert!(!result.stderr.is_empty());
    assert!(!rejected.exists());
}

#[test]
fn corrupt_payload_verification_and_cat_fail_without_stdout_data() {
    let temp = TestDir::new();
    let path = temp.build("corrupt.glue");
    let payload = fs::read(fixture().join("input/assets/message.txt")).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let start = bytes
        .windows(payload.len())
        .position(|window| window == payload)
        .unwrap();
    bytes[start] ^= 1;
    fs::write(&path, bytes).unwrap();

    for args in [
        vec![arg("verify"), path.as_os_str()],
        vec![arg("cat"), path.as_os_str(), arg("assets/message.txt")],
    ] {
        let result = temp.run(&args);
        assert_status(&result, 1);
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
    }
}

#[test]
fn doctor_run_and_standalone_build_report_unavailable_execution_without_artifacts() {
    let temp = TestDir::new();
    let doctor = temp.run(&[arg("doctor")]);
    assert_status(&doctor, 0);
    let doctor_text = diagnostic(&doctor).to_ascii_lowercase();
    assert!(doctor_text.contains("available"));
    assert!(doctor_text.contains("pending") || doctor_text.contains("unavailable"));

    let path = temp.build("diagnostics.glue");
    let before = tree_snapshot(&temp.0);
    for command in ["doctor", "run"] {
        let result = temp.run(&[arg(command), path.as_os_str()]);
        assert_status(&result, 2);
        let text = diagnostic(&result).to_ascii_lowercase();
        assert!(
            text.contains("g1") || text.contains("unimplemented") || text.contains("unavailable")
        );
        assert_eq!(tree_snapshot(&temp.0), before);
    }

    let standalone = temp.0.join("standalone.glue");
    let result = temp.build_output(&fixture().join("manifest.json"), &standalone, true);
    assert_status(&result, 2);
    assert!(!diagnostic(&result).is_empty());
    assert!(!standalone.exists());
    assert_eq!(tree_snapshot(&temp.0), before);
}

#[test]
fn malformed_archives_unknown_commands_and_invalid_flags_report_errors() {
    let temp = TestDir::new();
    let malformed = temp.0.join("malformed.glue");
    fs::write(&malformed, b"not a glue archive").unwrap();
    for command in ["inspect", "verify", "doctor", "run"] {
        let result = temp.run(&[arg(command), malformed.as_os_str()]);
        assert_status(&result, 1);
        assert!(!result.stderr.is_empty());
    }
    for args in [
        vec![arg("unknown-command")],
        vec![arg("build"), arg("--unknown-flag")],
        vec![arg("inspect"), malformed.as_os_str(), arg("--raw")],
        vec![arg("cat"), malformed.as_os_str()],
    ] {
        let result = temp.run(&args);
        assert_status(&result, 1);
        assert!(!result.stderr.is_empty());
    }
}

#[test]
fn help_and_version_succeed_without_an_archive() {
    let temp = TestDir::new();
    let help = temp.run(&[arg("--help")]);
    assert_status(&help, 0);
    let help = diagnostic(&help);
    for command in [
        "build",
        "inspect",
        "verify",
        "cat",
        "explain-size",
        "doctor",
        "run",
    ] {
        assert!(help.contains(command), "help omits {command}: {help}");
    }
    let version = temp.run(&[arg("--version")]);
    assert_status(&version, 0);
    assert!(diagnostic(&version).contains(env!("CARGO_PKG_VERSION")));
    assert!(tree_snapshot(&temp.0).is_empty());
}
