use glue_format::*;
use std::collections::{BTreeMap, BTreeSet};

fn resource(bytes: &[u8]) -> ResourceSpec {
    ResourceSpec {
        size: bytes.len() as u64,
        sha256: digest(bytes),
        compression: Compression::Stored,
    }
}

fn target(os: OperatingSystem) -> TargetProfile {
    TargetProfile {
        os,
        arch: if os == OperatingSystem::Macos {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        },
        minimum_os_version: match os {
            OperatingSystem::Linux => "6.1",
            OperatingSystem::Macos => "14.0",
            OperatingSystem::Windows => "10.0.19041",
            OperatingSystem::Freebsd => "14.4",
        }
        .to_owned(),
        abi: match os {
            OperatingSystem::Linux => TargetAbi::Glibc {
                minimum_version: "2.28".to_owned(),
            },
            OperatingSystem::Macos => TargetAbi::Darwin,
            OperatingSystem::Windows => TargetAbi::Msvc,
            OperatingSystem::Freebsd => TargetAbi::Freebsd,
        },
        page_sizes: BTreeSet::from([4096]),
        cpu_features: BTreeSet::new(),
    }
}

fn source() -> SourcePin {
    SourcePin {
        release: "20261001".to_owned(),
        revision: Some("immutable-source-commit".to_owned()),
        artifact: "https://example.invalid/pinned-runtime.tar.gz".to_owned(),
        sha256: digest(b"original upstream artifact"),
        variant: "shared-install-only".to_owned(),
    }
}

fn manifest() -> Manifest {
    Manifest {
        schema_version: SCHEMA_VERSION,
        app_id: "contract.fixture".to_owned(),
        entrypoint: "main".to_owned(),
        targets: BTreeMap::from([("mac-arm64".to_owned(), target(OperatingSystem::Macos))]),
        resources: BTreeMap::from([
            ("app/main.py".to_owned(), resource(b"print(1)")),
            (
                "runtime/libpython.dylib".to_owned(),
                resource(b"synthetic libpython"),
            ),
            (
                "runtime/stdlib.pack".to_owned(),
                resource(b"synthetic stdlib"),
            ),
            (
                "native/math.dylib".to_owned(),
                resource(b"synthetic native module"),
            ),
        ]),
        runtimes: BTreeMap::from([(
            "python".to_owned(),
            RuntimeSpec {
                target: "mac-arm64".to_owned(),
                build_id: "cpython-3.13.8-fixture-build".to_owned(),
                abi: RuntimeAbi::Python {
                    version: RuntimeVersion {
                        major: 3,
                        minor: 13,
                        patch: 8,
                    },
                    gil: GilMode::Conventional,
                    debug: false,
                },
                provisioning: Provisioning::Bundled {
                    provider: BundledProvider::PythonBuildStandalone,
                    source: source(),
                    runtime_library: "runtime/libpython.dylib".to_owned(),
                    stdlib: "runtime/stdlib.pack".to_owned(),
                },
                required_features: BTreeSet::from([
                    LoaderFeature::FunctionExports,
                    LoaderFeature::DataExports,
                ]),
            },
        )]),
        components: BTreeMap::from([(
            "main".to_owned(),
            ComponentSpec {
                runtime: "python".to_owned(),
                entry_point: "app/main.py".to_owned(),
                native_modules: BTreeSet::from(["math".to_owned()]),
            },
        )]),
        native_modules: BTreeMap::from([(
            "math".to_owned(),
            NativeModuleSpec {
                target: "mac-arm64".to_owned(),
                resource: "native/math.dylib".to_owned(),
                format: NativeFormat::MachO,
                namespace: "python.extensions".to_owned(),
                runtime: Some("python".to_owned()),
                dependencies: vec![
                    DependencySpec::Runtime {
                        runtime: "python".to_owned(),
                    },
                    DependencySpec::OperatingSystem {
                        import: "libsystem".to_owned(),
                    },
                ],
                required_features: BTreeSet::from([LoaderFeature::FunctionExports]),
            },
        )]),
        host_imports: BTreeMap::from([(
            "libsystem".to_owned(),
            HostImportSpec::OperatingSystem {
                target: "mac-arm64".to_owned(),
                library: "/usr/lib/libSystem.B.dylib".to_owned(),
                symbols: BTreeSet::from(["getpid".to_owned()]),
            },
        )]),
    }
}

fn rejects(change: impl FnOnce(&mut Manifest)) -> FormatError {
    let mut value = manifest();
    change(&mut value);
    value
        .validate()
        .expect_err("invalid contract must reject before execution")
}

#[test]
fn digest_uses_sha256_payload_identity() {
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(source().sha256, resource(b"normalized runtime").sha256);
}

#[test]
fn canonical_json_round_trip_is_deterministic() {
    let value = manifest();
    let bytes = value.to_json().unwrap();
    assert_eq!(value, Manifest::from_json(&bytes).unwrap());
    assert_eq!(bytes, value.to_json().unwrap());
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("{\"app_id\":"));
    assert!(text.find("\"app/main.py\"").unwrap() < text.find("\"native/math.dylib\"").unwrap());
}

#[test]
fn duplicate_json_keys_reject_at_every_depth_and_after_escape_decoding() {
    for input in [
        r#"{"schema_version":0,"schema_version":0}"#,
        r#"{"resources":{"a":{"size":1,"size":2}}}"#,
        r#"{"native_modules":{"a":{"dependencies":[{"class":"runtime","class":"host_module"}]}}}"#,
        r#"{"app_id":"one","app_\u0069d":"two"}"#,
    ] {
        let error = Manifest::from_json(input.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate JSON key"), "{input}: {error}");
    }
}

#[test]
fn unknown_fields_and_values_reject_in_nested_contracts() {
    let original = serde_json::to_value(manifest()).unwrap();
    for pointer in [
        "",
        "/runtimes/python",
        "/runtimes/python/provisioning",
        "/runtimes/python/abi",
        "/targets/mac-arm64",
        "/native_modules/math",
        "/host_imports/libsystem",
    ] {
        let mut value = original.clone();
        let object = if pointer.is_empty() {
            value.as_object_mut().unwrap()
        } else {
            value.pointer_mut(pointer).unwrap().as_object_mut().unwrap()
        };
        object.insert("silent_fallback".to_owned(), true.into());
        assert!(
            Manifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut value = original;
    value["resources"]["app/main.py"]["compression"] = "zstd".into();
    assert!(Manifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn json_limits_trailing_data_and_unknown_schema_reject() {
    let mut bytes = manifest().to_json().unwrap();
    bytes.extend_from_slice(b"{}");
    assert!(Manifest::from_json(&bytes).is_err());
    assert!(Manifest::from_json(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    assert!(matches!(
        rejects(|m| m.schema_version = 1),
        FormatError::UnsupportedSchemaVersion(1)
    ));
}

#[test]
fn resource_paths_reject_traversal_devices_and_ambiguous_names() {
    for path in [
        "",
        "/absolute",
        "a/",
        "a//b",
        "./a",
        "a/../b",
        "C:/a",
        "a\\b",
        "a\0b",
        "a\nb",
        "caf\u{e9}",
        "a?b",
        "name.",
        "name ",
        "NUL",
        "con.txt",
        "COM1.py",
        "lpt9.so",
        "aux/sub",
        "CONIN$.txt",
    ] {
        assert!(ResourcePath::new(path).is_err(), "accepted {path:?}");
    }
    for path in [
        "app/main.py",
        "assets/read me.txt",
        ".metadata/value",
        "com10.lua",
    ] {
        assert_eq!(ResourcePath::new(path).unwrap().as_str(), path);
    }
    assert!(ResourcePath::new("a".repeat(256)).is_err());
}

#[test]
fn collisions_include_implicit_directories_and_file_directory_conflicts() {
    for paths in [
        vec!["a", "a"],
        vec!["a", "A"],
        vec!["Dir/a", "dir/b"],
        vec!["a", "a/b"],
        vec!["a/b", "a"],
    ] {
        assert!(validate_resource_paths(paths).is_err());
    }
    validate_resource_paths(["assets/a", "assets/b", "app/main.py"]).unwrap();
    rejects(|m| {
        m.resources
            .insert("App/other.py".to_owned(), resource(b"x"));
    });
}

#[test]
fn hashes_and_all_resource_references_are_validated() {
    for hash in ["", "ABCDEF", &"A".repeat(64), &"g".repeat(64)] {
        rejects(|m| m.resources.get_mut("app/main.py").unwrap().sha256 = hash.to_owned());
    }
    rejects(|m| {
        m.resources.remove("app/main.py");
    });
    rejects(|m| {
        m.resources.remove("native/math.dylib");
    });
    rejects(|m| {
        if let Provisioning::Bundled {
            runtime_library, ..
        } = &mut m.runtimes.get_mut("python").unwrap().provisioning
        {
            *runtime_library = "missing".to_owned();
        }
    });
    rejects(|m| m.entrypoint = "missing".to_owned());
    rejects(|m| m.components.get_mut("main").unwrap().runtime = "missing".to_owned());
    rejects(|m| {
        m.components
            .get_mut("main")
            .unwrap()
            .native_modules
            .insert("missing".to_owned());
    });
}

#[test]
fn target_profiles_reject_inconsistent_abi_and_unbounded_assumptions() {
    rejects(|m| m.targets.get_mut("mac-arm64").unwrap().abi = TargetAbi::Msvc);
    rejects(|m| m.targets.get_mut("mac-arm64").unwrap().minimum_os_version = "latest".to_owned());
    for sizes in [
        BTreeSet::new(),
        BTreeSet::from([0]),
        BTreeSet::from([8193]),
        BTreeSet::from([131072]),
    ] {
        rejects(|m| m.targets.get_mut("mac-arm64").unwrap().page_sizes = sizes);
    }
    rejects(|m| m.runtimes.get_mut("python").unwrap().target = "missing".to_owned());
    rejects(|m| m.native_modules.get_mut("math").unwrap().format = NativeFormat::Pe);
    rejects(|m| {
        m.native_modules
            .get_mut("math")
            .unwrap()
            .required_features
            .insert(LoaderFeature::PeStaticTls);
    });
}

#[test]
fn target_slices_cannot_be_crossed_by_dependency_or_component_edges() {
    rejects(|m| {
        m.targets
            .insert("linux-x64".to_owned(), target(OperatingSystem::Linux));
        let native = m.native_modules.get_mut("math").unwrap();
        native.target = "linux-x64".to_owned();
        native.format = NativeFormat::Elf;
    });
    rejects(|m| {
        m.targets
            .insert("linux-x64".to_owned(), target(OperatingSystem::Linux));
        let HostImportSpec::OperatingSystem { target, .. } =
            m.host_imports.get_mut("libsystem").unwrap()
        else {
            unreachable!()
        };
        *target = "linux-x64".to_owned();
    });
}

#[test]
fn python_gil_debug_and_provider_mismatch_reject() {
    rejects(|m| {
        let RuntimeAbi::Python { gil, .. } = &mut m.runtimes.get_mut("python").unwrap().abi else {
            unreachable!()
        };
        *gil = GilMode::FreeThreaded;
    });
    rejects(|m| {
        let RuntimeAbi::Python { debug, .. } = &mut m.runtimes.get_mut("python").unwrap().abi
        else {
            unreachable!()
        };
        *debug = true;
    });
    rejects(|m| {
        let Provisioning::Bundled { provider, .. } =
            &mut m.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        *provider = BundledProvider::LuaSource;
    });
}

#[test]
fn source_pins_reject_moving_aliases_missing_identity_and_invalid_hashes() {
    for release in ["", "latest", "main", "^3.13", "3.*"] {
        rejects(|m| {
            let Provisioning::Bundled { source, .. } =
                &mut m.runtimes.get_mut("python").unwrap().provisioning
            else {
                unreachable!()
            };
            source.release = release.to_owned();
        });
    }
    rejects(|m| {
        let Provisioning::Bundled { source, .. } =
            &mut m.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        source.sha256 = "not-a-digest".to_owned();
    });
    rejects(|m| m.runtimes.get_mut("python").unwrap().build_id.clear());
}

#[test]
fn host_provider_requires_explicit_absolute_target_paths() {
    let mut m = manifest();
    m.runtimes.get_mut("python").unwrap().provisioning = Provisioning::Host {
        runtime_library: "/opt/python/lib/libpython3.13.dylib".to_owned(),
        stdlib: "/opt/python/lib/python3.13".to_owned(),
        discovery: HostDiscovery::ExplicitPaths,
    };
    m.validate().unwrap();
    for path in [
        "libpython.dylib",
        "~/libpython.dylib",
        "$PYTHON/libpython.dylib",
        "/opt/../libpython.dylib",
    ] {
        let mut invalid = m.clone();
        let Provisioning::Host {
            runtime_library, ..
        } = &mut invalid.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        *runtime_library = path.to_owned();
        assert!(invalid.validate().is_err(), "{path}");
    }
    let mut json = serde_json::to_value(m).unwrap();
    json["runtimes"]["python"]["provisioning"]["fallback"] = "bundled".into();
    assert!(Manifest::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn windows_host_paths_do_not_depend_on_build_host_path_semantics() {
    let mut m = manifest();
    m.targets
        .insert("mac-arm64".to_owned(), target(OperatingSystem::Windows));
    m.native_modules.get_mut("math").unwrap().format = NativeFormat::Pe;
    m.runtimes.get_mut("python").unwrap().provisioning = Provisioning::Host {
        runtime_library: "C:\\Python\\python313.dll".to_owned(),
        stdlib: "C:\\Python\\Lib".to_owned(),
        discovery: HostDiscovery::ExplicitPaths,
    };
    m.validate().unwrap();
    for path in [
        "C:python313.dll",
        "\\Windows\\python313.dll",
        "/opt/python313.dll",
        "C:\\Python\\..\\python313.dll",
    ] {
        let mut invalid = m.clone();
        let Provisioning::Host {
            runtime_library, ..
        } = &mut invalid.runtimes.get_mut("python").unwrap().provisioning
        else {
            unreachable!()
        };
        *runtime_library = path.to_owned();
        assert!(invalid.validate().is_err(), "{path}");
    }
}

#[test]
fn freebsd_requires_a_bundled_producer_distinct_from_pbs() {
    let mut m = manifest();
    m.targets
        .insert("mac-arm64".to_owned(), target(OperatingSystem::Freebsd));
    m.native_modules.get_mut("math").unwrap().format = NativeFormat::Elf;
    assert!(m.validate().is_err());
    let Provisioning::Bundled { provider, .. } =
        &mut m.runtimes.get_mut("python").unwrap().provisioning
    else {
        unreachable!()
    };
    *provider = BundledProvider::CpythonSource;
    m.validate().unwrap();
}

#[test]
fn lua_and_node_abi_contracts_round_trip_and_require_pins() {
    let mut m = manifest();
    let runtime = m.runtimes.get_mut("python").unwrap();
    runtime.abi = RuntimeAbi::Lua {
        version: RuntimeVersion {
            major: 5,
            minor: 4,
            patch: 8,
        },
        integer_bits: 64,
        number: LuaNumber::Float64,
    };
    let Provisioning::Bundled { provider, .. } = &mut runtime.provisioning else {
        unreachable!()
    };
    *provider = BundledProvider::LuaSource;
    m.validate().unwrap();
    let mut invalid = m.clone();
    let RuntimeAbi::Lua { integer_bits, .. } = &mut invalid.runtimes.get_mut("python").unwrap().abi
    else {
        unreachable!()
    };
    *integer_bits = 32;
    assert!(invalid.validate().is_err());
    let runtime = m.runtimes.get_mut("python").unwrap();
    runtime.abi = RuntimeAbi::Node {
        version: RuntimeVersion {
            major: 26,
            minor: 9,
            patch: 0,
        },
        node_api: 10,
        addon_abi: 145,
        bridge_revision: "bridge-commit-fixture".to_owned(),
    };
    let Provisioning::Bundled { provider, .. } = &mut runtime.provisioning else {
        unreachable!()
    };
    *provider = BundledProvider::NodeSource;
    assert_eq!(m, Manifest::from_json(&m.to_json().unwrap()).unwrap());
    let Provisioning::Bundled { source, .. } =
        &mut m.runtimes.get_mut("python").unwrap().provisioning
    else {
        unreachable!()
    };
    source.revision = None;
    assert!(m.validate().is_err());
}

#[test]
fn missing_misclassified_and_duplicate_dependencies_reject() {
    rejects(|m| {
        m.native_modules.get_mut("math").unwrap().dependencies.push(
            DependencySpec::ArchivedModule {
                module: "missing".to_owned(),
            },
        )
    });
    rejects(|m| {
        m.native_modules
            .get_mut("math")
            .unwrap()
            .dependencies
            .push(DependencySpec::HostModule {
                import: "libsystem".to_owned(),
            })
    });
    rejects(|m| {
        m.native_modules
            .get_mut("math")
            .unwrap()
            .dependencies
            .push(DependencySpec::Runtime {
                runtime: "python".to_owned(),
            })
    });
    rejects(|m| {
        m.native_modules
            .get_mut("math")
            .unwrap()
            .dependencies
            .push(DependencySpec::Runtime {
                runtime: "missing".to_owned(),
            })
    });
}

#[test]
fn declared_host_modules_cannot_mix_runtime_identities() {
    let mut m = manifest();
    m.host_imports.insert(
        "host-extension".to_owned(),
        HostImportSpec::HostModule {
            target: "mac-arm64".to_owned(),
            path: "/opt/extensions/example.so".to_owned(),
            runtime: Some("python".to_owned()),
            sha256: Some(digest(b"host extension")),
        },
    );
    m.native_modules
        .get_mut("math")
        .unwrap()
        .dependencies
        .push(DependencySpec::HostModule {
            import: "host-extension".to_owned(),
        });
    m.validate().unwrap();
    m.runtimes
        .insert("second-python".to_owned(), m.runtimes["python"].clone());
    let HostImportSpec::HostModule { runtime, .. } =
        m.host_imports.get_mut("host-extension").unwrap()
    else {
        unreachable!()
    };
    *runtime = Some("second-python".to_owned());
    assert!(m.validate().is_err());
}

#[test]
fn neutral_native_modules_cannot_hide_runtime_bindings() {
    // Explicit annotations allow local edge checks to enforce the same identity
    // through dependency chains, including cycles, without executing libraries.
    rejects(|m| m.native_modules.get_mut("math").unwrap().runtime = None);
    rejects(|m| {
        let mut neutral = m.native_modules["math"].clone();
        neutral.runtime = None;
        neutral.dependencies = vec![DependencySpec::ArchivedModule {
            module: "math".to_owned(),
        }];
        m.native_modules.insert("neutral".to_owned(), neutral);
    });
    rejects(|m| {
        m.host_imports.insert(
            "bound-host".to_owned(),
            HostImportSpec::HostModule {
                target: "mac-arm64".to_owned(),
                path: "/opt/extension.so".to_owned(),
                runtime: Some("python".to_owned()),
                sha256: None,
            },
        );
        let native = m.native_modules.get_mut("math").unwrap();
        native.runtime = None;
        native.dependencies = vec![DependencySpec::HostModule {
            import: "bound-host".to_owned(),
        }];
    });
}

#[test]
fn capability_declarations_and_cycles_are_metadata_not_loader_success() {
    let mut m = manifest();
    m.native_modules
        .get_mut("math")
        .unwrap()
        .required_features
        .insert(LoaderFeature::Tls);
    m.native_modules
        .get_mut("math")
        .unwrap()
        .dependencies
        .push(DependencySpec::ArchivedModule {
            module: "math".to_owned(),
        });
    // A later loader must preflight capabilities and handle/diagnose cycles. The
    // format validator proves references, never that constructors can safely run.
    m.validate().unwrap();
}

fn linked_manifest() -> Manifest {
    linked_manifest_with_version(4, 8)
}

fn linked_manifest_with_version(minor: u16, patch: u16) -> Manifest {
    let release = format!("5.{minor}.{patch}");
    let mut m = manifest();
    let mut runtime = m.runtimes.remove("python").unwrap();
    runtime.build_id = format!("linked-lua-{release}-fixture");
    runtime.abi = RuntimeAbi::Lua {
        version: RuntimeVersion {
            major: 5,
            minor,
            patch,
        },
        integer_bits: 64,
        number: LuaNumber::Float64,
    };
    runtime.provisioning = Provisioning::Linked {
        provider: BundledProvider::LuaSource,
        source: SourcePin {
            release: release.clone(),
            revision: None,
            artifact: format!("https://www.lua.org/ftp/lua-{release}.tar.gz"),
            sha256: digest(b"synthetic Lua source artifact"),
            variant: "static-int64-float64".to_owned(),
        },
    };
    m.runtimes.insert("lua".to_owned(), runtime);
    m.components.get_mut("main").unwrap().runtime = "lua".to_owned();
    let native = m.native_modules.get_mut("math").unwrap();
    native.runtime = Some("lua".to_owned());
    for dependency in &mut native.dependencies {
        if let DependencySpec::Runtime { runtime } = dependency {
            *runtime = "lua".to_owned();
        }
    }
    m.resources.remove("runtime/libpython.dylib");
    m.resources.remove("runtime/stdlib.pack");
    m
}

#[test]
fn linked_lua_round_trips_without_runtime_library_or_stdlib_resources() {
    let m = linked_manifest();
    m.validate().unwrap();
    let bytes = m.to_json().unwrap();
    assert_eq!(m, Manifest::from_json(&bytes).unwrap());
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let spec = &json["runtimes"]["lua"]["provisioning"];
    assert_eq!(spec["mode"], "linked");
    assert!(spec.get("runtime_library").is_none());
    assert!(spec.get("stdlib").is_none());
}

#[test]
fn linked_lua55_round_trips_and_preserves_its_exact_release() {
    let m = linked_manifest_with_version(5, 1);
    let bytes = m.to_json().unwrap();
    let decoded = Manifest::from_json(&bytes).unwrap();
    assert_eq!(decoded, m);
    assert!(matches!(
        decoded.runtimes["lua"].abi,
        RuntimeAbi::Lua {
            version: RuntimeVersion {
                major: 5,
                minor: 5,
                patch: 1,
            },
            integer_bits: 64,
            number: LuaNumber::Float64,
        }
    ));
    let Provisioning::Linked { source, .. } = &decoded.runtimes["lua"].provisioning else {
        unreachable!()
    };
    assert_eq!(source.release, "5.5.1");
    for release in ["5.4.9", "5.5", "5.5.0", "5.5.01"] {
        let mut invalid = m.clone();
        let Provisioning::Linked { source, .. } =
            &mut invalid.runtimes.get_mut("lua").unwrap().provisioning
        else {
            unreachable!()
        };
        source.release = release.to_owned();
        assert!(invalid.validate().is_err(), "{release}");
    }
}

#[test]
fn lua55_requires_fixed_numeric_abi_and_unknown_minor_is_rejected() {
    for (integer_bits, number) in [(32, LuaNumber::Float64), (64, LuaNumber::Float32)] {
        let mut m = linked_manifest_with_version(5, 1);
        let RuntimeAbi::Lua {
            integer_bits: selected_integer,
            number: selected_number,
            ..
        } = &mut m.runtimes.get_mut("lua").unwrap().abi
        else {
            unreachable!()
        };
        *selected_integer = integer_bits;
        *selected_number = number;
        assert!(m.validate().is_err(), "{integer_bits}/{number:?}");
    }
    // The source release matches this unsupported ABI, so the version check
    // itself must reject it rather than relying on a mismatched source pin.
    let unknown = linked_manifest_with_version(6, 1);
    assert!(unknown.validate().is_err());
}

#[test]
fn linked_lua_rejects_discovery_fallback_and_archived_runtime_fields() {
    let original = serde_json::to_value(linked_manifest()).unwrap();
    for field in ["runtime_library", "stdlib", "discovery", "fallback"] {
        let mut json = original.clone();
        json["runtimes"]["lua"]["provisioning"][field] = "unrequested-provider".into();
        assert!(
            Manifest::from_json(&serde_json::to_vec(&json).unwrap()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn linked_lua_requires_official_provider_and_fixed_numeric_abi() {
    for provider in [
        BundledProvider::PythonBuildStandalone,
        BundledProvider::CpythonSource,
        BundledProvider::NodeSource,
        BundledProvider::Custom,
    ] {
        let mut m = linked_manifest();
        let Provisioning::Linked {
            provider: selected, ..
        } = &mut m.runtimes.get_mut("lua").unwrap().provisioning
        else {
            unreachable!()
        };
        *selected = provider;
        assert!(m.validate().is_err(), "{provider:?}");
    }
    for abi in [
        RuntimeAbi::Python {
            version: RuntimeVersion {
                major: 3,
                minor: 13,
                patch: 8,
            },
            gil: GilMode::Conventional,
            debug: false,
        },
        RuntimeAbi::Node {
            version: RuntimeVersion {
                major: 26,
                minor: 9,
                patch: 0,
            },
            node_api: 10,
            addon_abi: 145,
            bridge_revision: "fixture-bridge-revision".to_owned(),
        },
        RuntimeAbi::Lua {
            version: RuntimeVersion {
                major: 5,
                minor: 4,
                patch: 8,
            },
            integer_bits: 32,
            number: LuaNumber::Float64,
        },
        RuntimeAbi::Lua {
            version: RuntimeVersion {
                major: 5,
                minor: 4,
                patch: 8,
            },
            integer_bits: 64,
            number: LuaNumber::Float32,
        },
        RuntimeAbi::Lua {
            version: RuntimeVersion {
                major: 5,
                minor: 3,
                patch: 8,
            },
            integer_bits: 64,
            number: LuaNumber::Float64,
        },
    ] {
        let mut m = linked_manifest();
        m.runtimes.get_mut("lua").unwrap().abi = abi;
        assert!(m.validate().is_err());
    }
}

#[test]
fn linked_lua_requires_exact_source_release_and_valid_source_pin() {
    for release in ["5.4.7", "5.4", "5.4.08", "lua-5.4.8", "latest"] {
        let mut m = linked_manifest();
        let Provisioning::Linked { source, .. } =
            &mut m.runtimes.get_mut("lua").unwrap().provisioning
        else {
            unreachable!()
        };
        source.release = release.to_owned();
        assert!(m.validate().is_err(), "{release}");
    }
    for field in ["release", "artifact", "variant", "sha256", "revision"] {
        let mut m = linked_manifest();
        let Provisioning::Linked { source, .. } =
            &mut m.runtimes.get_mut("lua").unwrap().provisioning
        else {
            unreachable!()
        };
        match field {
            "release" => source.release.clear(),
            "artifact" => source.artifact.clear(),
            "variant" => source.variant.clear(),
            "sha256" => source.sha256.clear(),
            "revision" => source.revision = Some(String::new()),
            _ => unreachable!(),
        }
        assert!(m.validate().is_err(), "{field}");
    }
    let mut m = linked_manifest();
    let RuntimeAbi::Lua { version, .. } = &mut m.runtimes.get_mut("lua").unwrap().abi else {
        unreachable!()
    };
    version.patch = 7;
    assert!(m.validate().is_err());
}

#[test]
fn explicit_host_and_archived_lua_specs_do_not_turn_into_linked_specs() {
    let mut m = linked_manifest();
    m.runtimes.get_mut("lua").unwrap().provisioning = Provisioning::Host {
        runtime_library: "/opt/lua/liblua.so".to_owned(),
        stdlib: "/opt/lua/stdlib".to_owned(),
        discovery: HostDiscovery::ExplicitPaths,
    };
    let decoded = Manifest::from_json(&m.to_json().unwrap()).unwrap();
    assert!(matches!(
        decoded.runtimes["lua"].provisioning,
        Provisioning::Host { .. }
    ));
    let Provisioning::Linked { source, .. } = linked_manifest()
        .runtimes
        .remove("lua")
        .unwrap()
        .provisioning
    else {
        unreachable!()
    };
    m.runtimes.get_mut("lua").unwrap().provisioning = Provisioning::Bundled {
        provider: BundledProvider::LuaSource,
        source,
        runtime_library: "runtime/liblua.so".to_owned(),
        stdlib: "runtime/lua-stdlib.pack".to_owned(),
    };
    // A linked runtime in the launcher cannot satisfy missing archived references.
    assert!(m.validate().is_err());
    m.resources.insert(
        "runtime/liblua.so".to_owned(),
        resource(b"synthetic archived Lua image"),
    );
    m.resources.insert(
        "runtime/lua-stdlib.pack".to_owned(),
        resource(b"synthetic archived Lua stdlib"),
    );
    let decoded = Manifest::from_json(&m.to_json().unwrap()).unwrap();
    assert!(matches!(
        decoded.runtimes["lua"].provisioning,
        Provisioning::Bundled { .. }
    ));
}
