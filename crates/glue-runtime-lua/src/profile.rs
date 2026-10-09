//! Exact acquisition and host prerequisites for the initial linked Lua profile.
//!
//! Capability validation never selects another provider or starts a runtime.
//! Unavailable capabilities are distinct from inconsistent build/source/target
//! declarations so callers can report unsupported execution separately.

use glue_format::{
    BundledProvider, LuaNumber, Manifest, OperatingSystem, Provisioning, RuntimeAbi,
    RuntimeVersion, SourcePin, TargetAbi,
};

#[allow(unsafe_code)]
#[path = "platform.rs"]
mod platform;

// The crate's feature guards require exactly one selected profile. Defining the
// default constants when lua55 is absent keeps invalid-feature diagnostics clear.
#[cfg(all(not(feature = "lua55"), not(feature = "linux-native")))]
pub const BUILD_ID: &str = "glue-lua54-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64";
#[cfg(all(feature = "lua55", not(feature = "linux-native")))]
pub const BUILD_ID: &str = "glue-lua55-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64";
#[cfg(all(not(feature = "lua55"), feature = "linux-native"))]
pub const BUILD_ID: &str = "glue-lua54-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64";
#[cfg(all(feature = "lua55", feature = "linux-native"))]
pub const BUILD_ID: &str = "glue-lua55-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64";

#[cfg(not(feature = "lua55"))]
pub const LUA_RELEASE: &str = "5.4.9";
#[cfg(feature = "lua55")]
pub const LUA_RELEASE: &str = "5.5.1";

#[cfg(not(feature = "lua55"))]
pub const LUA_VERSION: &str = "Lua 5.4";
#[cfg(feature = "lua55")]
pub const LUA_VERSION: &str = "Lua 5.5";

#[cfg(not(feature = "lua55"))]
pub const LUA_MINOR: u16 = 4;
#[cfg(feature = "lua55")]
pub const LUA_MINOR: u16 = 5;

#[cfg(not(feature = "lua55"))]
pub const LUA_PATCH: u16 = 9;
#[cfg(feature = "lua55")]
pub const LUA_PATCH: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error("linked Lua execution is unsupported: {0}")]
    Unsupported(String),
    #[error("invalid linked Lua acquisition: {0}")]
    Invalid(String),
}

/// The original source crate pin, distinct from any archive resource digest.
pub fn source_pin() -> SourcePin {
    SourcePin {
        release: LUA_RELEASE.to_owned(),
        revision: None,
        artifact: "https://static.crates.io/crates/lua-src/lua-src-551.0.2.crate".to_owned(),
        sha256: "d400ffef0e3d4d29287092bdc5a276d0bf468b2c69709d5bab0d469312d9f947".to_owned(),
        variant: format!("lua5{LUA_MINOR}-static-int64-float64"),
    }
}

/// Validate the selected entrypoint against the exact linked runtime and this
/// host, returning its canonical archive resource key only on success.
pub fn validate(manifest: &Manifest) -> Result<String, CapabilityError> {
    let entry = validate_declaration(manifest)?;
    let host = platform::observe()?;
    validate_target(manifest, &host)?;
    Ok(entry)
}

fn validate_declaration(manifest: &Manifest) -> Result<String, CapabilityError> {
    let component = manifest
        .components
        .get(&manifest.entrypoint)
        .ok_or_else(|| invalid("selected entrypoint component does not exist"))?;
    let runtime = manifest
        .runtimes
        .get(&component.runtime)
        .ok_or_else(|| invalid("selected component runtime does not exist"))?;
    if manifest.components.len() > 1 || manifest.runtimes.len() > 1 || manifest.targets.len() > 1 {
        return Err(unsupported(
            "this profile requires exactly one component, runtime and target; mixed execution and workers are pending",
        ));
    }
    if !matches!(runtime.abi, RuntimeAbi::Lua { .. }) {
        return Err(unsupported("the selected runtime is not Lua"));
    }
    let source = match &runtime.provisioning {
        Provisioning::Linked { provider, source } => {
            if *provider != BundledProvider::LuaSource {
                return Err(invalid("the linked provider must be lua_source"));
            }
            source
        }
        Provisioning::Host { .. } => {
            return Err(unsupported(
                "host Lua acquisition is pending; a linked runtime is never substituted",
            ));
        }
        Provisioning::Bundled { .. } => {
            return Err(unsupported(
                "archived Lua acquisition is pending; a linked runtime is never substituted",
            ));
        }
    };
    if runtime.build_id != BUILD_ID {
        return Err(invalid(format!("runtime build ID must be {BUILD_ID:?}")));
    }
    if source != &source_pin() {
        return Err(invalid(
            "runtime source does not match the exact compiled source pin",
        ));
    }
    let expected_abi = RuntimeAbi::Lua {
        version: RuntimeVersion {
            major: 5,
            minor: LUA_MINOR,
            patch: LUA_PATCH,
        },
        integer_bits: 64,
        number: LuaNumber::Float64,
    };
    if runtime.abi != expected_abi {
        return Err(invalid(format!(
            "runtime ABI must be Lua {LUA_RELEASE} with 64-bit integers and float64 numbers"
        )));
    }
    manifest
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    #[cfg(not(feature = "linux-native"))]
    if !manifest.native_modules.is_empty() || !component.native_modules.is_empty() {
        return Err(unsupported("native Lua modules are pending"));
    }
    #[cfg(not(feature = "linux-native"))]
    if !runtime.required_features.is_empty() {
        return Err(unsupported(
            "native loader feature requirements are pending",
        ));
    }
    #[cfg(not(feature = "linux-native"))]
    if !manifest.host_imports.is_empty() {
        return Err(unsupported("declared host imports are pending"));
    }
    #[cfg(feature = "linux-native")]
    glue_native::validate_manifest(manifest).map_err(|error| match error {
        glue_native::NativeError::Unsupported(message) => unsupported(message),
        error => invalid(error.to_string()),
    })?;
    Ok(component.entry_point.clone())
}

fn validate_target(manifest: &Manifest, host: &platform::Host) -> Result<(), CapabilityError> {
    // Declaration validation above proves both selected references exist.
    let component = &manifest.components[&manifest.entrypoint];
    let runtime = &manifest.runtimes[&component.runtime];
    let target = &manifest.targets[&runtime.target];
    if !matches!(target.os, OperatingSystem::Macos | OperatingSystem::Linux) {
        return Err(unsupported(
            "only macOS Darwin and GNU Linux profiles have been observed",
        ));
    }
    if target.os != host.os || target.arch != host.arch {
        return Err(invalid(format!(
            "selected target {:?}/{:?} differs from this host {:?}/{:?}",
            target.os, target.arch, host.os, host.arch
        )));
    }
    match (&target.abi, host.os) {
        (TargetAbi::Darwin, OperatingSystem::Macos) => {}
        (TargetAbi::Glibc { minimum_version }, OperatingSystem::Linux) => {
            let actual = host
                .glibc_version
                .as_deref()
                .ok_or_else(|| unsupported("GNU libc could not be queried"))?;
            check_floor(actual, minimum_version, "GNU libc")?;
        }
        _ => {
            return Err(invalid(
                "target ABI differs from the compiled Darwin/GNU libc profile",
            ));
        }
    }
    check_floor(&host.os_version, &target.minimum_os_version, "OS")?;
    if !target.page_sizes.contains(&host.page_size) {
        return Err(invalid(format!(
            "host page size {} is not declared by the selected target",
            host.page_size
        )));
    }
    if !target.cpu_features.is_empty() {
        return Err(unsupported(
            "explicit CPU feature requirements cannot yet be verified",
        ));
    }
    Ok(())
}

fn check_floor(actual: &str, minimum: &str, name: &str) -> Result<(), CapabilityError> {
    let actual_version = numeric_version(actual)
        .map_err(|_| unsupported(format!("cannot interpret host {name} version {actual:?}")))?;
    let minimum_version = numeric_version(minimum)?;
    if actual_version < minimum_version {
        return Err(invalid(format!(
            "host {name} version {actual} is below declared minimum {minimum}"
        )));
    }
    Ok(())
}

fn numeric_version(value: &str) -> Result<[u32; 4], CapabilityError> {
    let mut result = [0; 4];
    for (index, part) in value.split('.').enumerate() {
        if index >= result.len()
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid(format!("invalid numeric version {value:?}")));
        }
        result[index] = part
            .parse()
            .map_err(|_| invalid(format!("invalid numeric version {value:?}")))?;
    }
    Ok(result)
}

fn invalid(message: impl Into<String>) -> CapabilityError {
    CapabilityError::Invalid(message.into())
}

fn unsupported(message: impl Into<String>) -> CapabilityError {
    CapabilityError::Unsupported(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use glue_format::{
        Architecture, ComponentSpec, Compression, GilMode, HostDiscovery, LoaderFeature,
        ResourceSpec, RuntimeSpec, TargetProfile, digest,
    };
    #[cfg(not(feature = "linux-native"))]
    use glue_format::{HostImportSpec, NativeFormat, NativeModuleSpec};
    use std::collections::{BTreeMap, BTreeSet};

    fn linux_host() -> platform::Host {
        platform::Host {
            os: OperatingSystem::Linux,
            arch: if cfg!(feature = "linux-native") {
                Architecture::Aarch64
            } else {
                Architecture::X86_64
            },
            os_version: if cfg!(feature = "linux-native") {
                "6.3.0"
            } else {
                "6.1.0"
            }
            .to_owned(),
            glibc_version: Some("2.36".to_owned()),
            page_size: 4096,
        }
    }

    fn fixture(host: &platform::Host) -> Manifest {
        Manifest {
            schema_version: 0,
            app_id: "lua.profile.fixture".to_owned(),
            entrypoint: "main".to_owned(),
            targets: BTreeMap::from([(
                "current".to_owned(),
                TargetProfile {
                    os: host.os,
                    arch: host.arch,
                    minimum_os_version: host.os_version.clone(),
                    abi: match host.os {
                        OperatingSystem::Macos => TargetAbi::Darwin,
                        OperatingSystem::Linux => TargetAbi::Glibc {
                            minimum_version: host.glibc_version.clone().unwrap(),
                        },
                        _ => unreachable!("test fixture requires a supported host"),
                    },
                    page_sizes: BTreeSet::from([host.page_size]),
                    cpu_features: BTreeSet::new(),
                },
            )]),
            resources: ["app/main.lua", "app/helper.lua"]
                .into_iter()
                .map(|path| {
                    (
                        path.to_owned(),
                        ResourceSpec {
                            size: 8,
                            sha256: digest(b"return 1"),
                            compression: Compression::Stored,
                        },
                    )
                })
                .collect(),
            runtimes: BTreeMap::from([(
                "lua".to_owned(),
                RuntimeSpec {
                    target: "current".to_owned(),
                    build_id: BUILD_ID.to_owned(),
                    abi: RuntimeAbi::Lua {
                        version: RuntimeVersion {
                            major: 5,
                            minor: LUA_MINOR,
                            patch: LUA_PATCH,
                        },
                        integer_bits: 64,
                        number: LuaNumber::Float64,
                    },
                    provisioning: Provisioning::Linked {
                        provider: BundledProvider::LuaSource,
                        source: source_pin(),
                    },
                    required_features: BTreeSet::new(),
                },
            )]),
            components: BTreeMap::from([(
                "main".to_owned(),
                ComponentSpec {
                    runtime: "lua".to_owned(),
                    entry_point: "app/main.lua".to_owned(),
                    native_modules: BTreeSet::new(),
                },
            )]),
            native_modules: BTreeMap::new(),
            host_imports: BTreeMap::new(),
        }
    }

    fn validate_on(manifest: &Manifest, host: &platform::Host) -> Result<String, CapabilityError> {
        let entry = validate_declaration(manifest)?;
        validate_target(manifest, host)?;
        Ok(entry)
    }

    fn is_invalid(result: Result<String, CapabilityError>) {
        assert!(
            matches!(result, Err(CapabilityError::Invalid(_))),
            "{result:?}"
        );
    }

    fn is_unsupported(result: Result<String, CapabilityError>) {
        assert!(
            matches!(result, Err(CapabilityError::Unsupported(_))),
            "{result:?}"
        );
    }

    #[test]
    fn exact_source_profile_accepts_selected_entry_and_additional_lua_resources() {
        let host = linux_host();
        let manifest = fixture(&host);
        manifest.validate().unwrap();
        assert_eq!(validate_on(&manifest, &host).unwrap(), "app/main.lua");
    }

    #[cfg(any(
        all(
            not(feature = "linux-native"),
            any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))
        ),
        all(
            feature = "linux-native",
            target_os = "linux",
            target_env = "gnu",
            target_arch = "aarch64"
        )
    ))]
    #[test]
    fn exact_profile_accepts_the_observed_host() {
        let host = platform::observe().unwrap();
        assert!(host.page_size.is_power_of_two());
        assert_eq!(validate(&fixture(&host)).unwrap(), "app/main.lua");
    }

    #[test]
    fn build_abi_and_every_source_pin_field_are_exact() {
        let host = linux_host();
        for field in [
            "build", "release", "revision", "artifact", "sha256", "variant", "provider", "patch",
            "integer", "number",
        ] {
            let mut manifest = fixture(&host);
            let runtime = manifest.runtimes.get_mut("lua").unwrap();
            match field {
                "build" => runtime.build_id.push_str("-different"),
                "patch" => {
                    runtime.abi = RuntimeAbi::Lua {
                        version: RuntimeVersion {
                            major: 5,
                            minor: LUA_MINOR,
                            patch: LUA_PATCH - 1,
                        },
                        integer_bits: 64,
                        number: LuaNumber::Float64,
                    }
                }
                "integer" => {
                    runtime.abi = RuntimeAbi::Lua {
                        version: RuntimeVersion {
                            major: 5,
                            minor: LUA_MINOR,
                            patch: LUA_PATCH,
                        },
                        integer_bits: 32,
                        number: LuaNumber::Float64,
                    }
                }
                "number" => {
                    runtime.abi = RuntimeAbi::Lua {
                        version: RuntimeVersion {
                            major: 5,
                            minor: LUA_MINOR,
                            patch: LUA_PATCH,
                        },
                        integer_bits: 64,
                        number: LuaNumber::Float32,
                    }
                }
                _ => {
                    let Provisioning::Linked { provider, source } = &mut runtime.provisioning
                    else {
                        unreachable!()
                    };
                    match field {
                        "release" => source.release = format!("5.{LUA_MINOR}.{}", LUA_PATCH - 1),
                        "revision" => source.revision = Some("unapproved".to_owned()),
                        "artifact" => source.artifact.push_str("?different"),
                        "sha256" => source.sha256 = "0".repeat(64),
                        "variant" => source.variant.push_str("-different"),
                        "provider" => *provider = BundledProvider::Custom,
                        _ => unreachable!(),
                    }
                }
            }
            is_invalid(validate_on(&manifest, &host));
        }
    }

    #[test]
    fn another_minor_source_or_build_never_substitutes_for_the_compiled_profile() {
        let host = linux_host();
        let (minor, patch) = if LUA_MINOR == 4 { (5, 1) } else { (4, 9) };
        let release = format!("5.{minor}.{patch}");
        let build =
            format!("glue-lua5{minor}-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64");
        let mut other_source = source_pin();
        other_source.release = release;
        other_source.variant = format!("lua5{minor}-static-int64-float64");
        let other_abi = RuntimeAbi::Lua {
            version: RuntimeVersion {
                major: 5,
                minor,
                patch,
            },
            integer_bits: 64,
            number: LuaNumber::Float64,
        };
        for mismatch in ["abi", "source", "build", "all"] {
            let mut manifest = fixture(&host);
            let runtime = manifest.runtimes.get_mut("lua").unwrap();
            if mismatch == "abi" || mismatch == "all" {
                runtime.abi = other_abi.clone();
            }
            if mismatch == "build" || mismatch == "all" {
                runtime.build_id = build.clone();
            }
            if mismatch == "source" || mismatch == "all" {
                runtime.provisioning = Provisioning::Linked {
                    provider: BundledProvider::LuaSource,
                    source: other_source.clone(),
                };
            }
            // Both complete declarations are format-valid; only acquisition
            // against this exact compiled launcher rejects the other profile.
            if mismatch == "all" {
                manifest.validate().unwrap();
            }
            is_invalid(validate_on(&manifest, &host));
        }
    }

    #[test]
    fn previous_rust_thunk_adapter_identity_requires_rebuilding_archives() {
        let host = linux_host();
        let mut manifest = fixture(&host);
        manifest.runtimes.get_mut("lua").unwrap().build_id =
            format!("glue-lua5{LUA_MINOR}-source-v1/mlua-0.12.2/lua-src-551.0.2/int64-float64");
        manifest.validate().unwrap();
        is_invalid(validate_on(&manifest, &host));
    }

    #[test]
    fn host_and_archived_lua_do_not_fall_back_to_linked_lua() {
        let host = linux_host();
        for provisioning in [
            Provisioning::Host {
                runtime_library: "/fixture/liblua.so".to_owned(),
                stdlib: "/fixture/lua".to_owned(),
                discovery: HostDiscovery::ExplicitPaths,
            },
            Provisioning::Bundled {
                provider: BundledProvider::LuaSource,
                source: source_pin(),
                runtime_library: "app/main.lua".to_owned(),
                stdlib: "app/helper.lua".to_owned(),
            },
        ] {
            let mut manifest = fixture(&host);
            manifest.runtimes.get_mut("lua").unwrap().provisioning = provisioning;
            manifest.validate().unwrap();
            is_unsupported(validate_on(&manifest, &host));
        }
    }

    #[test]
    fn python_and_node_are_explicitly_unsupported() {
        let host = linux_host();
        for abi in [
            RuntimeAbi::Python {
                version: RuntimeVersion {
                    major: 3,
                    minor: 13,
                    patch: 0,
                },
                gil: GilMode::Conventional,
                debug: false,
            },
            RuntimeAbi::Node {
                version: RuntimeVersion {
                    major: 22,
                    minor: 0,
                    patch: 0,
                },
                node_api: 9,
                addon_abi: 127,
                bridge_revision: "fixture".to_owned(),
            },
        ] {
            let mut manifest = fixture(&host);
            let runtime = manifest.runtimes.get_mut("lua").unwrap();
            runtime.abi = abi;
            runtime.provisioning = Provisioning::Host {
                runtime_library: "/fixture/runtime.so".to_owned(),
                stdlib: "/fixture/stdlib".to_owned(),
                discovery: HostDiscovery::ExplicitPaths,
            };
            manifest.validate().unwrap();
            is_unsupported(validate_on(&manifest, &host));
        }
    }

    #[test]
    #[cfg(not(feature = "linux-native"))]
    fn native_modules_imports_and_features_are_pending() {
        let host = linux_host();
        let mut manifest = fixture(&host);
        manifest
            .runtimes
            .get_mut("lua")
            .unwrap()
            .required_features
            .insert(LoaderFeature::FunctionExports);
        is_unsupported(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.host_imports.insert(
            "libc".to_owned(),
            HostImportSpec::OperatingSystem {
                target: "current".to_owned(),
                library: "libc.so.6".to_owned(),
                symbols: BTreeSet::from(["strlen".to_owned()]),
            },
        );
        is_unsupported(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.native_modules.insert(
            "native".to_owned(),
            NativeModuleSpec {
                target: "current".to_owned(),
                resource: "app/helper.lua".to_owned(),
                format: NativeFormat::Elf,
                namespace: "lua.fixture".to_owned(),
                runtime: Some("lua".to_owned()),
                dependencies: Vec::new(),
                required_features: BTreeSet::new(),
            },
        );
        manifest
            .components
            .get_mut("main")
            .unwrap()
            .native_modules
            .insert("native".to_owned());
        is_unsupported(validate_on(&manifest, &host));
    }

    #[test]
    #[cfg(not(feature = "linux-native"))]
    fn target_os_arch_abi_and_prerequisite_floors_must_match() {
        let host = linux_host();
        for field in ["os", "arch", "abi", "os_floor", "libc_floor", "page"] {
            let mut manifest = fixture(&host);
            let target = manifest.targets.get_mut("current").unwrap();
            match field {
                "os" => {
                    target.os = OperatingSystem::Macos;
                    target.abi = TargetAbi::Darwin;
                }
                "arch" => target.arch = Architecture::Aarch64,
                "abi" => {
                    target.abi = TargetAbi::Musl {
                        minimum_version: "1.2".to_owned(),
                    }
                }
                "os_floor" => target.minimum_os_version = "6.1.1".to_owned(),
                "libc_floor" => {
                    target.abi = TargetAbi::Glibc {
                        minimum_version: "2.37".to_owned(),
                    }
                }
                "page" => target.page_sizes = BTreeSet::from([16384]),
                _ => unreachable!(),
            }
            manifest.validate().unwrap();
            is_invalid(validate_on(&manifest, &host));
        }
    }

    #[cfg(feature = "linux-native")]
    #[test]
    fn native_profile_is_distinct_and_rejects_unobserved_target_features() {
        let host = linux_host();
        assert!(BUILD_ID.contains("native-linux-v1"));
        let mut manifest = fixture(&host);
        manifest.runtimes.get_mut("lua").unwrap().build_id =
            format!("glue-lua5{LUA_MINOR}-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64");
        is_invalid(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.targets.get_mut("current").unwrap().arch = Architecture::X86_64;
        is_unsupported(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest
            .runtimes
            .get_mut("lua")
            .unwrap()
            .required_features
            .insert(LoaderFeature::Tls);
        is_unsupported(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest
            .targets
            .get_mut("current")
            .unwrap()
            .minimum_os_version = "6.2".to_owned();
        is_invalid(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.targets.get_mut("current").unwrap().abi = TargetAbi::Glibc {
            minimum_version: "2.37".to_owned(),
        };
        is_invalid(validate_on(&manifest, &host));
    }

    #[test]
    fn unobserved_targets_and_cpu_requirements_are_unsupported() {
        let host = linux_host();
        for (os, abi) in [
            (OperatingSystem::Windows, TargetAbi::Msvc),
            (OperatingSystem::Freebsd, TargetAbi::Freebsd),
        ] {
            let mut manifest = fixture(&host);
            let target = manifest.targets.get_mut("current").unwrap();
            target.os = os;
            target.abi = abi;
            manifest.validate().unwrap();
            is_unsupported(validate_on(&manifest, &host));
        }
        let mut manifest = fixture(&host);
        manifest
            .targets
            .get_mut("current")
            .unwrap()
            .cpu_features
            .insert("sse4_2".to_owned());
        is_unsupported(validate_on(&manifest, &host));
    }

    #[test]
    fn workers_mixed_runtimes_and_multiple_targets_are_unsupported() {
        let host = linux_host();
        for field in ["component", "runtime", "target"] {
            let mut manifest = fixture(&host);
            match field {
                "component" => {
                    manifest
                        .components
                        .insert("other".to_owned(), manifest.components["main"].clone());
                }
                "runtime" => {
                    manifest
                        .runtimes
                        .insert("other".to_owned(), manifest.runtimes["lua"].clone());
                }
                "target" => {
                    manifest
                        .targets
                        .insert("other".to_owned(), manifest.targets["current"].clone());
                }
                _ => unreachable!(),
            }
            manifest.validate().unwrap();
            is_unsupported(validate_on(&manifest, &host));
        }
    }

    #[test]
    fn malformed_selected_references_are_invalid() {
        let host = linux_host();
        let mut manifest = fixture(&host);
        manifest.entrypoint = "missing".to_owned();
        is_invalid(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.components.get_mut("main").unwrap().runtime = "missing".to_owned();
        is_invalid(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.runtimes.get_mut("lua").unwrap().target = "missing".to_owned();
        is_invalid(validate_on(&manifest, &host));
        let mut manifest = fixture(&host);
        manifest.targets.clear();
        is_invalid(validate_on(&manifest, &host));
    }

    #[test]
    fn prerequisite_version_comparison_uses_numeric_components_and_zero_padding() {
        check_floor("14.0.0", "14", "OS").unwrap();
        check_floor("2.36", "2.9", "GNU libc").unwrap();
        assert!(matches!(
            check_floor("2.9", "2.36", "GNU libc"),
            Err(CapabilityError::Invalid(_))
        ));
        assert!(matches!(
            check_floor("unknown", "1", "OS"),
            Err(CapabilityError::Unsupported(_))
        ));
        assert!(matches!(
            check_floor("14", "14.bad", "OS"),
            Err(CapabilityError::Invalid(_))
        ));
    }
}
