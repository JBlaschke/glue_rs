//! Portable closure-admission tests. All native images are synthesized in
//! memory; no checked-in binary, ignored target file, loader, or constructor is
//! needed to establish rejection before loading.

use super::*;
use crate::elf::tests::Fixture;
use glue_format::{Archive, Compression, LOCATOR_SIZE, ResourceSpec, digest, write_archive};
use std::io::Cursor;

const TARGET: &str = "linux-arm64-linked";
const ROOT: &str = "fixture";
const ROOT_RESOURCE: &str = "native/libfixture.so";

fn set64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn payloads(fixture: Fixture) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("app/main.lua".into(), b"return true".to_vec()),
        (ROOT_RESOURCE.into(), fixture.bytes),
    ])
}

fn manifest(payloads: &BTreeMap<String, Vec<u8>>) -> Manifest {
    let mut manifest = Manifest::from_json(include_bytes!(
        "../../../fixtures/lua-linked/manifest.linux-arm64.json"
    ))
    .unwrap();
    manifest.app_id = "native.closure.tests".into();
    manifest.targets.get_mut(TARGET).unwrap().minimum_os_version = "6.3".into();
    manifest.runtimes.get_mut("lua").unwrap().build_id =
        "glue-lua54-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64".into();
    manifest.resources = payloads
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression: Compression::Stored,
                },
            )
        })
        .collect();
    manifest.components.get_mut("main").unwrap().native_modules = BTreeSet::from([ROOT.into()]);
    manifest.native_modules = BTreeMap::from([(
        ROOT.into(),
        glue_format::NativeModuleSpec {
            target: TARGET.into(),
            resource: ROOT_RESOURCE.into(),
            format: NativeFormat::Elf,
            namespace: "linked-lua".into(),
            runtime: Some("lua".into()),
            dependencies: vec![
                DependencySpec::Runtime {
                    runtime: "lua".into(),
                },
                DependencySpec::OperatingSystem {
                    import: "libc".into(),
                },
            ],
            required_features: BTreeSet::from([
                LoaderFeature::FunctionExports,
                LoaderFeature::DataExports,
                LoaderFeature::Constructors,
                LoaderFeature::SymbolVersions,
                LoaderFeature::RuntimeAliases,
            ]),
        },
    )]);
    manifest.host_imports = BTreeMap::from([(
        "libc".into(),
        HostImportSpec::OperatingSystem {
            target: TARGET.into(),
            library: "libc.so.6".into(),
            symbols: BTreeSet::from(["getpid".into()]),
        },
    )]);
    manifest.validate().unwrap();
    manifest
}

fn archive_bytes(manifest: &Manifest, payloads: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    write_archive(Cursor::new(Vec::new()), manifest, payloads)
        .unwrap()
        .into_inner()
}

fn resources(
    manifest: &Manifest,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Resources<Cursor<Vec<u8>>> {
    Resources::new(
        Archive::open(Cursor::new(archive_bytes(manifest, payloads))).unwrap(),
        0,
    )
}

fn prepare(
    manifest: &Manifest,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<NativePlan, NativeError> {
    NativePlan::prepare(&mut resources(manifest, payloads), &BTreeSet::new())
}

fn rejection(error: NativeError, expected: &str) {
    assert!(
        error.to_string().contains(expected),
        "expected {expected:?}, got {error}"
    );
}

fn add_dependency(manifest: &mut Manifest, resource: &str) {
    let mut dependency = manifest.native_modules[ROOT].clone();
    dependency.resource = resource.into();
    dependency.runtime = None;
    dependency.dependencies.clear();
    dependency.required_features = BTreeSet::from([LoaderFeature::FunctionExports]);
    manifest
        .native_modules
        .insert("dependency".into(), dependency);
}

fn add_resource(manifest: &mut Manifest, name: &str) {
    manifest.resources.insert(
        name.into(),
        ResourceSpec {
            size: 1,
            sha256: digest(b"x"),
            compression: Compression::Stored,
        },
    );
}

#[test]
fn prepares_a_complete_immutable_plan_without_loading_on_the_host() {
    let payloads = payloads(Fixture::new());
    let manifest = manifest(&payloads);
    validate_manifest(&manifest).unwrap();
    let plan = prepare(&manifest, &payloads).unwrap();
    assert_eq!(plan.order, [ROOT]);
    assert_eq!(plan.images.len(), 1);
    assert_eq!(plan.roots[ROOT].symbol, "luaopen_fixture");
    assert_eq!(plan.roots[ROOT].resource, ROOT_RESOURCE);
    let image = &plan.images[ROOT];
    assert_eq!(&*image.bytes, payloads[ROOT_RESOURCE]);
    assert!(image.facts.has_constructors);
    let getpid = image.facts.symbol("getpid").unwrap();
    assert!(
        matches!(&image.providers[&getpid.index], Provider::OperatingSystem { symbol, version } if symbol=="getpid" && version=="GLIBC_2.17")
    );
}

#[test]
fn declaration_rejects_namespace_target_and_page_profile() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    let mut value = baseline.clone();
    value.native_modules.get_mut(ROOT).unwrap().namespace = "another-scope".into();
    rejection(
        validate_manifest(&value).unwrap_err(),
        "namespace linked-lua",
    );
    let mut value = baseline.clone();
    value.targets.get_mut(TARGET).unwrap().arch = Architecture::X86_64;
    rejection(validate_manifest(&value).unwrap_err(), "GNU Linux AArch64");
    let mut value = baseline.clone();
    value.targets.get_mut(TARGET).unwrap().page_sizes = BTreeSet::from([65536]);
    rejection(validate_manifest(&value).unwrap_err(), "4096-byte pages");
    let mut value = baseline.clone();
    value.targets.get_mut(TARGET).unwrap().minimum_os_version = "6.2".into();
    rejection(validate_manifest(&value).unwrap_err(), "6.3");
    let mut value = baseline;
    value
        .targets
        .insert("another-target".into(), value.targets[TARGET].clone());
    value.native_modules.get_mut(ROOT).unwrap().target = "another-target".into();
    rejection(validate_manifest(&value).unwrap_err(), "target");
}

#[test]
fn declaration_requires_one_linked_lua_runtime_with_the_fixed_numeric_abi() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    let host = Provisioning::Host {
        runtime_library: "/native-fixture/liblua.so".into(),
        stdlib: "/native-fixture/lua-stdlib".into(),
        discovery: glue_format::HostDiscovery::ExplicitPaths,
    };
    let mut value = baseline.clone();
    value.runtimes.get_mut("lua").unwrap().provisioning = host.clone();
    let error = validate_manifest(&value).unwrap_err();
    assert!(matches!(error, NativeError::Unsupported(_)));
    rejection(error, "linked lua_source provider");

    let mut value = baseline.clone();
    let runtime = value.runtimes.get_mut("lua").unwrap();
    runtime.provisioning = host;
    runtime.abi = RuntimeAbi::Python {
        version: glue_format::RuntimeVersion {
            major: 3,
            minor: 12,
            patch: 0,
        },
        gil: glue_format::GilMode::Conventional,
        debug: false,
    };
    let error = validate_manifest(&value).unwrap_err();
    assert!(matches!(error, NativeError::Unsupported(_)));
    rejection(error, "linked Lua with int64/float64 ABI");

    for (integer_bits, number) in [(32, LuaNumber::Float64), (64, LuaNumber::Float32)] {
        let mut value = baseline.clone();
        let RuntimeAbi::Lua {
            integer_bits: bits,
            number: representation,
            ..
        } = &mut value.runtimes.get_mut("lua").unwrap().abi
        else {
            unreachable!();
        };
        *bits = integer_bits;
        *representation = number;
        let error = validate_manifest(&value).unwrap_err();
        assert!(matches!(error, NativeError::Invalid(_)));
        rejection(error, "64-bit integers and float64");
    }

    for extra in ["component", "runtime", "target"] {
        let mut value = baseline.clone();
        match extra {
            "component" => {
                value
                    .components
                    .insert("worker".into(), value.components["main"].clone());
            }
            "runtime" => {
                value
                    .runtimes
                    .insert("worker".into(), value.runtimes["lua"].clone());
            }
            _ => {
                value
                    .targets
                    .insert("other-target".into(), value.targets[TARGET].clone());
            }
        }
        let error = validate_manifest(&value).unwrap_err();
        assert!(matches!(error, NativeError::Unsupported(_)));
        rejection(error, "exactly one component, runtime and target");
    }
}

#[test]
fn declarations_reject_unobserved_features_and_private_soname_violations() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    for feature in [
        LoaderFeature::Tls,
        LoaderFeature::Ifunc,
        LoaderFeature::NestedLoading,
        LoaderFeature::Unwind,
    ] {
        let mut value = baseline.clone();
        value
            .native_modules
            .get_mut(ROOT)
            .unwrap()
            .required_features
            .insert(feature);
        rejection(
            validate_manifest(&value).unwrap_err(),
            "unobserved loader feature",
        );
    }
    for resource in [
        "native/liblua.so",
        "native/libc.so",
        "native/not-private.so",
    ] {
        let mut value = baseline.clone();
        add_resource(&mut value, resource);
        value.native_modules.get_mut(ROOT).unwrap().resource = resource.into();
        rejection(validate_manifest(&value).unwrap_err(), "private lib*.so");
    }
}

#[test]
fn declaration_requires_exact_root_name_and_runtime_edge() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    let mut value = baseline.clone();
    let module = value.native_modules.remove(ROOT).unwrap();
    value.native_modules.insert("bad-name".into(), module);
    value.components.get_mut("main").unwrap().native_modules = BTreeSet::from(["bad-name".into()]);
    rejection(
        validate_manifest(&value).unwrap_err(),
        "ASCII dotted identifiers",
    );
    let mut value = baseline.clone();
    value
        .native_modules
        .get_mut(ROOT)
        .unwrap()
        .dependencies
        .retain(|edge| !matches!(edge, DependencySpec::Runtime { .. }));
    rejection(
        validate_manifest(&value).unwrap_err(),
        "one exact runtime edge",
    );
    let mut value = baseline;
    let module = value.native_modules.get_mut(ROOT).unwrap();
    module.runtime = None;
    module
        .dependencies
        .retain(|edge| !matches!(edge, DependencySpec::Runtime { .. }));
    rejection(
        validate_manifest(&value).unwrap_err(),
        "exact runtime binding",
    );
}

#[test]
fn rejects_cycles_unreachable_images_and_resource_or_soname_collisions() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    let mut value = baseline.clone();
    add_resource(&mut value, "native/libdependency.so");
    add_dependency(&mut value, "native/libdependency.so");
    rejection(
        validate_manifest(&value).unwrap_err(),
        "outside the selected component closure",
    );
    value
        .native_modules
        .get_mut(ROOT)
        .unwrap()
        .dependencies
        .push(DependencySpec::ArchivedModule {
            module: "dependency".into(),
        });
    let dependency = value.native_modules.get_mut("dependency").unwrap();
    dependency.runtime = Some("lua".into());
    dependency.dependencies = vec![
        DependencySpec::Runtime {
            runtime: "lua".into(),
        },
        DependencySpec::ArchivedModule {
            module: ROOT.into(),
        },
    ];
    rejection(validate_manifest(&value).unwrap_err(), "dependency cycle");
    for resource in [ROOT_RESOURCE, "another/libfixture.so"] {
        let mut value = baseline.clone();
        if resource != ROOT_RESOURCE {
            add_resource(&mut value, resource);
        }
        add_dependency(&mut value, resource);
        rejection(
            validate_manifest(&value).unwrap_err(),
            "duplicate native SONAME or resource",
        );
    }
}

#[test]
fn all_native_hashes_are_verified_before_inspecting_the_first_elf() {
    let mut payloads = payloads(Fixture::new());
    payloads.insert(
        "native/libdependency.so".into(),
        b"not an ELF image".to_vec(),
    );
    let mut manifest = manifest(&payloads);
    add_dependency(&mut manifest, "native/libdependency.so");
    manifest
        .native_modules
        .get_mut(ROOT)
        .unwrap()
        .dependencies
        .push(DependencySpec::ArchivedModule {
            module: "dependency".into(),
        });
    // The first image has a correct resource hash but invalid ELF. The last
    // image's declared SHA is changed without disturbing its valid ZIP/CRC.
    let mut bytes = archive_bytes(&manifest, &payloads);
    let original = manifest.to_json().unwrap();
    manifest.resources.get_mut(ROOT_RESOURCE).unwrap().sha256 = "0".repeat(64);
    let changed = manifest.to_json().unwrap();
    assert_eq!(changed.len(), original.len());
    let start = LOCATOR_SIZE as usize;
    bytes[start..start + changed.len()].copy_from_slice(&changed);
    let hash = digest(&changed);
    for index in 0..32 {
        bytes[32 + index] = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16).unwrap();
    }
    let mut resources = Resources::new(Archive::open(Cursor::new(bytes)).unwrap(), 0);
    rejection(
        NativePlan::prepare(&mut resources, &BTreeSet::new()).unwrap_err(),
        "SHA-256 verification",
    );
}

#[test]
fn rejects_undeclared_needed_and_undefined_imports() {
    let mut fixture = Fixture::new();
    let offset = 0x1100 + fixture.tags.len() * 16;
    set64(&mut fixture.bytes, offset, 1); // Extra DT_NEEDED before DT_NULL.
    set64(
        &mut fixture.bytes,
        offset + 8,
        fixture.names["other.so"] as u64,
    );
    let payloads = payloads(fixture);
    let manifest = manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "ELF NEEDED differs",
    );
    let mut fixture = Fixture::new();
    fixture.rename_symbol(3, "other.so");
    let payloads = self::payloads(fixture);
    let manifest = self::manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "undeclared undefined symbol",
    );
}

#[test]
fn rejects_payload_lua_definitions_and_wrong_initializer_kind() {
    let mut fixture = Fixture::new();
    fixture.rename_symbol(2, "luaL_error");
    let symbol = fixture.symbol_mut(2);
    symbol[4] = 0x12;
    set64(symbol, 8, 0x820);
    let payloads = payloads(fixture);
    let manifest = manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "payload defines Lua runtime symbol",
    );
    let mut fixture = Fixture::new();
    fixture.symbol_mut(1)[4] = 0x11;
    let payloads = self::payloads(fixture);
    let manifest = self::manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "initializer must be a defined, visible function",
    );
    let mut fixture = Fixture::new();
    fixture.rename_symbol(1, "helper");
    let payloads = self::payloads(fixture);
    let manifest = self::manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "missing root initializer",
    );
}

#[test]
fn enforces_observed_constructor_version_and_export_features() {
    let payloads = payloads(Fixture::new());
    let baseline = manifest(&payloads);
    for (feature, diagnostic) in [
        (LoaderFeature::Constructors, "constructors are not declared"),
        (
            LoaderFeature::SymbolVersions,
            "symbol versions are not declared",
        ),
        (
            LoaderFeature::FunctionExports,
            "export feature is not declared",
        ),
        (LoaderFeature::DataExports, "export feature is not declared"),
    ] {
        let mut value = baseline.clone();
        value
            .native_modules
            .get_mut(ROOT)
            .unwrap()
            .required_features
            .remove(&feature);
        rejection(prepare(&value, &payloads).unwrap_err(), diagnostic);
    }
}

#[test]
fn checks_glibc_requirements_against_the_declared_floor() {
    let payloads = payloads(Fixture::new());
    let mut manifest = manifest(&payloads);
    manifest.targets.get_mut(TARGET).unwrap().abi = TargetAbi::Glibc {
        minimum_version: "2.16".into(),
    };
    rejection(prepare(&manifest, &payloads).unwrap_err(), "declared floor");
    manifest.targets.get_mut(TARGET).unwrap().abi = TargetAbi::Glibc {
        minimum_version: "2.17".into(),
    };
    prepare(&manifest, &payloads).unwrap();
}

fn runtime_import(name: &'static str) -> Fixture {
    let mut fixture = Fixture::new();
    fixture.rename_symbol(3, name);
    fixture.symbol_mut(3)[4] = 0x10; // Global undefined NOTYPE Lua import.
    fixture.set_version(3, 1);
    fixture
}

#[test]
fn linked_runtime_aliases_need_both_exact_exports_and_declared_feature() {
    let payloads = payloads(runtime_import("luaL_error"));
    let mut manifest = manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "undeclared undefined symbol",
    );
    let exports = BTreeSet::from(["luaL_error".into()]);
    NativePlan::prepare(&mut resources(&manifest, &payloads), &exports).unwrap();
    manifest
        .native_modules
        .get_mut(ROOT)
        .unwrap()
        .required_features
        .remove(&LoaderFeature::RuntimeAliases);
    rejection(
        NativePlan::prepare(&mut resources(&manifest, &payloads), &exports).unwrap_err(),
        "linked runtime aliases are not declared",
    );
}

#[test]
fn creating_or_closing_another_lua_state_is_rejected_even_if_exported() {
    for name in ["lua_newstate", "luaL_newstate", "lua_close"] {
        let payloads = payloads(runtime_import(name));
        let manifest = manifest(&payloads);
        let exports = BTreeSet::from([name.into()]);
        rejection(
            NativePlan::prepare(&mut resources(&manifest, &payloads), &exports).unwrap_err(),
            "state",
        );
    }
}

#[test]
fn compiler_weak_null_import_requires_weak_feature_declaration() {
    let mut fixture = Fixture::new();
    fixture.rename_symbol(3, "_ITM_registerTMCloneTable");
    fixture.symbol_mut(3)[4] = 0x20;
    fixture.set_version(3, 1);
    let payloads = payloads(fixture);
    let mut manifest = manifest(&payloads);
    rejection(prepare(&manifest, &payloads).unwrap_err(), "weak");
    manifest
        .native_modules
        .get_mut(ROOT)
        .unwrap()
        .required_features
        .insert(LoaderFeature::WeakSymbols);
    let plan = prepare(&manifest, &payloads).unwrap();
    let image = &plan.images[ROOT];
    let symbol = image.facts.symbol("_ITM_registerTMCloneTable").unwrap();
    assert!(matches!(image.providers[&symbol.index], Provider::WeakNull));
}

#[test]
fn local_lua_api_definitions_cannot_hide_from_runtime_substitution_checks() {
    let mut fixture = Fixture::new();
    fixture.rename_symbol(2, "luaL_error");
    let symbol = fixture.symbol_mut(2);
    symbol[4] = 0x02; // Defined LOCAL function, absent from exported symbols.
    set64(symbol, 8, 0x820);
    fixture.set_version(2, 0);
    // Relocate an allowed global instead of the local symbol; the ELF itself
    // remains valid so rejection specifically exercises closure ownership.
    let rela = fixture.tags[&7];
    let address =
        u64::from_le_bytes(fixture.bytes[rela + 8..rela + 16].try_into().unwrap()) as usize;
    set64(&mut fixture.bytes, address + 24 + 8, (1u64 << 32) | 1025);
    let payloads = payloads(fixture);
    let manifest = manifest(&payloads);
    rejection(
        prepare(&manifest, &payloads).unwrap_err(),
        "payload defines Lua runtime symbol luaL_error",
    );
}

#[test]
fn weak_definitions_and_resolved_os_or_runtime_imports_require_the_feature() {
    for identity in ["export", "operating-system", "runtime"] {
        let mut fixture = if identity == "runtime" {
            runtime_import("luaL_error")
        } else {
            Fixture::new()
        };
        let index = if identity == "export" { 1 } else { 3 };
        fixture.symbol_mut(index)[4] = if identity == "runtime" { 0x20 } else { 0x22 };
        let payloads = payloads(fixture);
        let mut manifest = manifest(&payloads);
        let exports = if identity == "runtime" {
            BTreeSet::from(["luaL_error".into()])
        } else {
            BTreeSet::new()
        };
        rejection(
            NativePlan::prepare(&mut resources(&manifest, &payloads), &exports).unwrap_err(),
            "weak",
        );
        manifest
            .native_modules
            .get_mut(ROOT)
            .unwrap()
            .required_features
            .insert(LoaderFeature::WeakSymbols);
        let plan = NativePlan::prepare(&mut resources(&manifest, &payloads), &exports).unwrap();
        let image = &plan.images[ROOT];
        if identity == "operating-system" {
            assert!(matches!(
                image.providers[&index],
                Provider::OperatingSystem { .. }
            ));
        } else if identity == "runtime" {
            assert!(matches!(image.providers[&index], Provider::Runtime(_)));
        } else {
            assert_eq!(
                image.facts.symbol("luaopen_fixture").unwrap().binding,
                SymbolBinding::Weak
            );
        }
    }
}
