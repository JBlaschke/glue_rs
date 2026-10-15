//! Bind the C layout boundary to the exact verified PBS installed header tree.

use sha2::{Digest, Sha256};
use std::{env, fmt::Write as _, fs, io::Read, path::PathBuf};

const HEADER_PINS: &str = include_str!("../../fixtures/python-bootstrap/header-pins.json");
const MACOS_HEADER_PINS: &str = include_str!("../../fixtures/python-host-macos/header-pins.json");
const FULL_ARTIFACT_SHA256: &str =
    "8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca";
const MACOS_INSTALL_ARTIFACT_SHA256: &str =
    "3338fcd572a670ec45ac9ef75480b95595ea9b6b5dd320952fcf5df185089941";

/// Exact cells whose verified installed header tree can compile the boundary.
#[derive(Clone, Copy, PartialEq)]
enum Cell {
    LinuxArm64,
    MacosArm64,
}
const OVERRIDE_ROOTS: &[&str] = &["CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=boundary/bridge.c");
    println!("cargo:rerun-if-changed=boundary/bridge.h");
    println!("cargo:rerun-if-changed=../../fixtures/python-bootstrap/header-pins.json");
    println!("cargo:rerun-if-changed=../../fixtures/python-host-macos/header-pins.json");
    println!("cargo:rerun-if-env-changed=GLUE_PYTHON_INCLUDE_DIR");
    println!("cargo:rustc-check-cfg=cfg(glue_python_boundary)");
    println!("cargo:rustc-check-cfg=cfg(glue_python_macos_host)");
    let target = required_env("TARGET");
    let enabled = env::var_os("CARGO_FEATURE_PBS_BOOTSTRAP").is_some();
    let cell = match target.as_str() {
        "aarch64-unknown-linux-gnu" => Some(Cell::LinuxArm64),
        "aarch64-apple-darwin" => Some(Cell::MacosArm64),
        _ => None,
    };
    let include_dir = env::var_os("GLUE_PYTHON_INCLUDE_DIR").map(PathBuf::from);
    // GNU Linux arm64 requires the header tree whenever the feature is enabled.
    // macOS arm64 compiles the same boundary only when a verified header tree is
    // named, so feature-enabled Mac builds without one keep validating only.
    let supported = match cell {
        Some(Cell::LinuxArm64) => true,
        Some(Cell::MacosArm64) => include_dir.is_some(),
        None => false,
    };
    let output_dir = PathBuf::from(required_env("OUT_DIR"));
    let mut provenance = format!(
        "glue stock PBS Python bootstrap boundary provenance v1\n\
         This is local build evidence, not a complete artifact fingerprint.\n\
         boundary=glue-python-bootstrap-c-boundary-4\n\
         api_revision=4\n\
         python_api_export_count=29\n\
         source=CPython 3.13.16 / PBS 20261009 / conventional GIL / non-debug\n\
         TARGET={target:?}\npbs_bootstrap_feature={enabled}\n\
         boundary_compiled={}\nboundary_cell={}\n",
        enabled && supported,
        match cell {
            Some(Cell::LinuxArm64) => "gnu-linux-arm64/full-artifact-headers",
            Some(Cell::MacosArm64) if include_dir.is_some() => {
                "macos-arm64/install-only-artifact-headers"
            }
            _ => "none",
        }
    );
    for name in [
        "HOST",
        "PROFILE",
        "OPT_LEVEL",
        "DEBUG",
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        writeln!(provenance, "{name}={:?}", env::var_os(name)).unwrap();
    }
    if !enabled || !supported {
        write_provenance(&output_dir, &provenance);
        return;
    }
    let host = required_env("HOST");
    track_overrides(&target, &host);
    for (name, value) in env::vars_os() {
        if name.to_str().is_some_and(is_override_name) && !value.is_empty() {
            panic!(
                "Python bootstrap boundary rejects nonempty compiler override {}; \
                 unset it to use the reviewed default C toolchain",
                name.to_string_lossy()
            );
        }
    }
    let input_dir =
        include_dir.expect("opt-in GNU Linux arm64 bootstrap requires GLUE_PYTHON_INCLUDE_DIR");
    assert!(
        input_dir.is_absolute(),
        "GLUE_PYTHON_INCLUDE_DIR must be absolute"
    );
    let (header_pins, artifact_sha256, artifact_label) = match cell {
        Some(Cell::MacosArm64) => (
            MACOS_HEADER_PINS,
            MACOS_INSTALL_ARTIFACT_SHA256,
            "install_only_artifact_sha256",
        ),
        _ => (HEADER_PINS, FULL_ARTIFACT_SHA256, "full_artifact_sha256"),
    };
    let pins: serde_json::Value = serde_json::from_str(header_pins)
        .expect("checked-in Python header pins must be valid JSON");
    assert_eq!(pins["artifact_sha256"], artifact_sha256);
    let files = pins["files"]
        .as_object()
        .expect("header pins need a file map");
    assert_eq!(
        files.len(),
        264,
        "the exact installed header tree is required"
    );
    let verified_dir = output_dir.join("verified-python-headers");
    if verified_dir.exists() {
        fs::remove_dir_all(&verified_dir).expect("cannot replace owned verified header build tree");
    }
    fs::create_dir(&verified_dir).expect("cannot create verified header build tree");
    let mut total = 0u64;
    for (relative, pin) in files {
        assert!(
            !relative.is_empty()
                && relative.len() <= 4096
                && relative.is_ascii()
                && !relative.contains(['\\', ':', '\0'])
                && relative
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "invalid checked-in header path"
        );
        let expected_size = pin["size"].as_u64().expect("header size missing");
        assert!(
            expected_size <= 512 * 1024,
            "header size exceeds the build bound"
        );
        total = total
            .checked_add(expected_size)
            .expect("header size overflow");
        assert!(
            total <= 4 * 1024 * 1024,
            "header tree exceeds the build bound"
        );
        let input = input_dir.join(relative);
        println!("cargo:rerun-if-changed={}", input.display());
        let mut bytes = Vec::new();
        fs::File::open(&input)
            .unwrap_or_else(|error| panic!("open pinned header {relative}: {error}"))
            .take(expected_size + 1)
            .read_to_end(&mut bytes)
            .unwrap_or_else(|error| panic!("read pinned header {relative}: {error}"));
        assert_eq!(
            bytes.len() as u64,
            expected_size,
            "header size mismatch: {relative}"
        );
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            Some(digest.as_str()),
            pin["sha256"].as_str(),
            "header SHA-256 mismatch: {relative}"
        );
        let destination = verified_dir.join(relative);
        fs::create_dir_all(destination.parent().unwrap())
            .expect("cannot create header subdirectory");
        fs::write(destination, &bytes).expect("cannot copy verified header build bytes");
    }
    let mut compiler_builder = cc::Build::new();
    compiler_builder.cargo_metadata(false);
    let compiler = compiler_builder
        .try_get_compiler()
        .expect("cannot identify default boundary compiler");
    let version = compiler
        .to_command()
        .arg("--version")
        .output()
        .expect("cannot query default boundary compiler");
    assert!(
        version.status.success(),
        "default boundary compiler --version failed"
    );
    writeln!(provenance, "{artifact_label}={artifact_sha256}").unwrap();
    writeln!(
        provenance,
        "header_pin_sha256={}",
        hex_digest(header_pins.as_bytes())
    )
    .unwrap();
    writeln!(
        provenance,
        "verified_installed_header_count={}",
        files.len()
    )
    .unwrap();
    writeln!(provenance, "verified_installed_header_bytes={total}").unwrap();
    writeln!(provenance, "default_cc_path={:?}", compiler.path()).unwrap();
    writeln!(provenance, "default_cc_args={:?}", compiler.args()).unwrap();
    writeln!(
        provenance,
        "default_cc_version={:?}",
        format!(
            "{}{}",
            String::from_utf8_lossy(&version.stdout),
            String::from_utf8_lossy(&version.stderr)
        )
    )
    .unwrap();
    writeln!(
        provenance,
        "compiler_override_policy=nonempty CC/CXX/CFLAGS/CXXFLAGS/CPPFLAGS variants rejected"
    )
    .unwrap();
    writeln!(
        provenance,
        "boundary_config=C11; warnings as errors; copied verified headers; no libpython link"
    )
    .unwrap();
    write_provenance(&output_dir, &provenance);
    cc::Build::new()
        .include(&verified_dir)
        .include("boundary")
        .file("boundary/bridge.c")
        .flag("-std=c11")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("glue_python_bootstrap_boundary");
    println!("cargo:rustc-cfg=glue_python_boundary");
    if cell == Some(Cell::MacosArm64) {
        println!("cargo:rustc-cfg=glue_python_macos_host");
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing Cargo build environment {name}"))
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_provenance(output_dir: &std::path::Path, provenance: &str) {
    let path = output_dir.join("python-bootstrap-provenance.txt");
    fs::write(&path, provenance).expect("cannot write Python boundary build provenance");
    println!(
        "cargo:rustc-env=GLUE_PYTHON_BUILD_PROVENANCE_PATH={}",
        path.display()
    );
}

fn is_override_name(name: &str) -> bool {
    let name = name
        .strip_prefix("HOST_")
        .or_else(|| name.strip_prefix("TARGET_"))
        .unwrap_or(name);
    name == "CRATE_CC_NO_DEFAULTS"
        || OVERRIDE_ROOTS.iter().any(|root| {
            name == *root
                || name
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('_'))
        })
}

fn track_overrides(target: &str, host: &str) {
    println!("cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS");
    for root in OVERRIDE_ROOTS {
        for name in [
            root.to_string(),
            format!("HOST_{root}"),
            format!("TARGET_{root}"),
        ] {
            println!("cargo:rerun-if-env-changed={name}");
        }
        for triple in [target, host] {
            println!("cargo:rerun-if-env-changed={root}_{triple}");
            println!(
                "cargo:rerun-if-env-changed={root}_{}",
                triple.replace('-', "_")
            );
        }
    }
    for (name, _) in env::vars_os() {
        if name.to_str().is_some_and(is_override_name) {
            println!("cargo:rerun-if-env-changed={}", name.to_string_lossy());
        }
    }
}
