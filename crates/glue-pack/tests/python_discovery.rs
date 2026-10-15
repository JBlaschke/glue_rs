#![cfg(feature = "python")]
use glue_pack::python::discovery::{DiscoveryOptions, discover, probe};
use std::{fs, path::PathBuf, time::Duration};

#[test]
#[ignore = "requires a supplied native runtime in GLUE_TEST_PYTHON"]
fn selected_runtime_and_venv_metadata_never_execute_site_hooks() {
    let python = std::env::var_os("GLUE_TEST_PYTHON").expect("supply GLUE_TEST_PYTHON");
    let selected = PathBuf::from(python);
    let facts = probe(&selected, Duration::from_secs(15)).unwrap();
    let root = std::env::temp_dir().join(format!("glue discovery café {}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(root.join("bin")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&selected, root.join("bin/python")).unwrap();
    fs::write(
        root.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\nversion = {}.{}.{}\n",
            facts.prefix.display(),
            facts.version[0],
            facts.version[1],
            facts.version[2]
        ),
    )
    .unwrap();
    let site = root.join(format!(
        "lib/python{}.{}/site-packages",
        facts.version[0], facts.version[1]
    ));
    fs::create_dir_all(site.join("plugin-1.dist-info")).unwrap();
    fs::write(
        site.join("trap.pth"),
        "import os; raise RuntimeError('site hook executed')\n",
    )
    .unwrap();
    fs::write(
        site.join("sitecustomize.py"),
        "raise RuntimeError('sitecustomize executed')\n",
    )
    .unwrap();
    fs::write(
        site.join("plugin-1.dist-info/entry_points.txt"),
        "[console_scripts]\nprobe = plugin.cli:main\n",
    )
    .unwrap();
    let options = DiscoveryOptions {
        environment: root.clone(),
        runtime: Some(selected),
        python_version: Some(format!("{}.{}", facts.version[0], facts.version[1])),
        target: None,
        inspect_only: false,
    };
    let found = discover(&options).unwrap();
    assert_eq!(found.runtime.soabi, facts.soabi);
    assert_eq!(found.console_scripts["probe"], "plugin.cli:main");
    assert_eq!(found.site_packages, [fs::canonicalize(site).unwrap()]);
    let wrong = DiscoveryOptions {
        python_version: Some("3.10".into()),
        ..options
    };
    assert!(discover(&wrong).unwrap_err().contains("does not satisfy"));
    assert_eq!(
        glue_pack::python::discovery::discover_diagnostic(&wrong)
            .unwrap_err()
            .code,
        glue_format::DiagnosticCode::RuntimeAbiMismatch
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn probe_rejects_malformed_output_and_bounds_time_and_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("glue probe bounds {}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (name, body, expected) in [
        ("malformed", "echo '{not json}'", "malformed"),
        ("timeout", "exec /bin/sleep 5", "timeout"),
        ("output", "exec /usr/bin/yes x", "output bound"),
    ] {
        let executable = root.join(name);
        fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let timeout = if name == "timeout" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(3)
        };
        let error = probe(&executable, timeout).unwrap_err();
        assert!(error.contains(expected), "{name}: {error}");
    }
    fs::remove_dir_all(root).unwrap();
}
