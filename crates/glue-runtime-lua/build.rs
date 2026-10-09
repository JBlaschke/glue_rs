//! Guard the initial linked Lua source profile and retain local build evidence.
//!
//! `BUILD_ID` is a logical source/ABI/profile identity, not an artifact hash.
//! Cargo feature unification is audited separately: lua-src does not expose
//! whether its optional `ucid` feature was enabled to dependent build scripts.

use std::{env, fmt::Write as _, fs, path::PathBuf};

const OVERRIDE_ROOTS: &[&str] = &["CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c/bridge.c");
    println!("cargo:rerun-if-changed=c/bridge.h");
    println!("cargo:rerun-if-changed=native-exports.txt");
    let (release, compatibility) = match (
        env::var_os("CARGO_FEATURE_LUA54").is_some(),
        env::var_os("CARGO_FEATURE_LUA55").is_some(),
    ) {
        (true, false) => ("5.4.9", "LUA_COMPAT_5_3"),
        (false, true) => ("5.5.1", "no compatibility define"),
        _ => panic!("linked Lua source profile requires exactly one of lua54 or lua55"),
    };
    let target = required_env("TARGET");
    let host = required_env("HOST");
    track_override_variables(&target, &host);

    // Inspect all names, including target suffixes outside this invocation's
    // host/target pair. Values are deliberately excluded from diagnostics.
    for (name, value) in env::vars_os() {
        if name.to_str().is_some_and(is_override_name) && !value.is_empty() {
            panic!(
                "linked Lua source profile rejects nonempty build override {}; \
                 unset it to use the audited default C compiler/configuration",
                name.to_string_lossy()
            );
        }
    }

    let mut builder = cc::Build::new();
    builder.cargo_metadata(false);
    let compiler = builder
        .try_get_compiler()
        .expect("cannot identify the default C compiler for linked Lua provenance");
    let output = compiler
        .to_command()
        .arg("--version")
        .output()
        .expect("cannot query the default C compiler for linked Lua provenance");
    assert!(
        output.status.success(),
        "default C compiler --version failed for linked Lua provenance"
    );
    let compiler_version = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let mut provenance = String::from(
        "glue linked Lua build provenance v2\n\
         This is local build evidence, not a complete artifact fingerprint.\n\
         boundary=glue-c-boundary-1\n\
         source_numeric_defaults=int64/float64\n\
         compiler_override_policy=nonempty CC/CXX/CFLAGS/CXXFLAGS/CPPFLAGS variants rejected\n\
         optional_ucid_feature=absence must be audited in Cargo feature graph\n",
    );
    writeln!(provenance, "source=lua-src-551.0.2/lua-{release}")
        .expect("writing to a String cannot fail");
    writeln!(
        provenance,
        "linux_native_feature={}",
        env::var_os("CARGO_FEATURE_LINUX_NATIVE").is_some()
    )
    .expect("writing to a String cannot fail");
    if env::var_os("CARGO_FEATURE_LINUX_NATIVE").is_some() {
        writeln!(
            provenance,
            "native_export_allowlist={:?}",
            include_str!("native-exports.txt")
        )
        .expect("writing to a String cannot fail");
    }
    for name in [
        "TARGET",
        "HOST",
        "PROFILE",
        "OPT_LEVEL",
        "DEBUG",
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        writeln!(provenance, "{name}={:?}", env::var_os(name))
            .expect("writing to a String cannot fail");
    }
    writeln!(
        provenance,
        "build_script_debug_assertions={}",
        cfg!(debug_assertions)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        provenance,
        "boundary_explicit_config=C11 when supported; warnings as errors; c/bridge.c"
    )
    .expect("writing to a String cannot fail");
    writeln!(provenance, "default_cc_path={:?}", compiler.path())
        .expect("writing to a String cannot fail");
    writeln!(provenance, "default_cc_args={:?}", compiler.args())
        .expect("writing to a String cannot fail");
    writeln!(provenance, "default_cc_version={compiler_version:?}")
        .expect("writing to a String cannot fail");
    // These are the source builder's explicit additions, distinct from the cc
    // defaults above. Whether -fno-common is supported is compiler-dependent.
    writeln!(
        provenance,
        "lua_src_explicit_config={compatibility}; target LUA_USE_*; \
         debug LUA_USE_APICHECK; conditional -fno-common; C source files"
    )
    .expect("writing to a String cannot fail");

    let path = PathBuf::from(required_env("OUT_DIR")).join("linked-lua-provenance.txt");
    fs::write(&path, provenance).expect("cannot write linked Lua build provenance");
    // Consumers can embed this text with include_str!(env!(...)); the path is
    // an output artifact, not a runtime lookup or a required installed file.
    println!(
        "cargo:rustc-env=GLUE_LUA_BUILD_PROVENANCE_PATH={}",
        path.display()
    );

    let version = if release == "5.4.9" {
        lua_src::Lua54
    } else {
        lua_src::Lua55
    };
    let artifacts = lua_src::Build::new().build(version);
    let mut boundary = cc::Build::new();
    if env::var_os("CARGO_FEATURE_LINUX_NATIVE").is_some() {
        boundary.define("GLUE_LUA_NATIVE", None);
    }
    boundary
        .include(artifacts.include_dir())
        .include("c")
        .file("c/bridge.c")
        .flag_if_supported("-std=c11")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("glue_lua_boundary");
    artifacts.print_cargo_metadata();
    if target.contains("linux") || target.ends_with("bsd") {
        println!("cargo:rustc-link-lib=m");
    }
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=dl");
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} missing from Cargo build environment"))
}

fn is_override_name(name: &str) -> bool {
    let name = name
        .strip_prefix("HOST_")
        .or_else(|| name.strip_prefix("TARGET_"))
        .unwrap_or(name);
    OVERRIDE_ROOTS.iter().any(|root| {
        name == *root
            || name
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('_'))
    }) || name == "CRATE_CC_NO_DEFAULTS"
}

fn track_override_variables(target: &str, host: &str) {
    println!("cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS");
    for root in OVERRIDE_ROOTS {
        println!("cargo:rerun-if-env-changed={root}");
        println!("cargo:rerun-if-env-changed=HOST_{root}");
        println!("cargo:rerun-if-env-changed=TARGET_{root}");
        for triple in [target, host] {
            println!("cargo:rerun-if-env-changed={root}_{triple}");
            println!(
                "cargo:rerun-if-env-changed={root}_{}",
                triple.replace('-', "_")
            );
        }
    }
    // Existing additional variants are tracked too. cc's effective override
    // names for this build are all covered above when initially unset.
    for (name, _) in env::vars_os() {
        if name.to_str().is_some_and(is_override_name) {
            println!("cargo:rerun-if-env-changed={}", name.to_string_lossy());
        }
    }
}
