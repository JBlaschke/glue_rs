//! Read-only prerequisites for the optional pinned profiles: the GNU Linux
//! arm64 cell and the explicit macOS arm64 host startup cell. These queries
//! never load Python, open host installations or claim the process execution
//! attempt. Legacy experiment entry points bypass them.

use glue_format::Manifest;
#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ),
    glue_python_macos_host
))]
use glue_format::{Architecture, OperatingSystem, TargetAbi, TargetProfile};

#[derive(Debug)]
pub(crate) enum ReadinessError {
    Unsupported(String),
    #[cfg_attr(
        not(any(
            all(
                feature = "pbs-bootstrap",
                target_os = "linux",
                target_arch = "aarch64",
                target_env = "gnu",
                glue_python_boundary
            ),
            glue_python_macos_host
        )),
        allow(dead_code)
    )]
    Invalid(String),
}

pub(crate) fn readiness(manifest: &Manifest) -> Result<(), ReadinessError> {
    #[cfg(not(feature = "pbs-bootstrap"))]
    {
        let _ = manifest;
        Err(unsupported(
            "the pinned Python pbs-bootstrap feature is not enabled",
        ))
    }
    #[cfg(all(
        feature = "pbs-bootstrap",
        not(all(target_os = "macos", target_arch = "aarch64")),
        not(all(
            target_os = "linux",
            target_arch = "aarch64",
            target_env = "gnu",
            glue_python_boundary
        ))
    ))]
    {
        let _ = manifest;
        Err(unsupported(
            "the pinned Python boundary is not compiled; requires the reviewed GNU Linux arm64 target",
        ))
    }
    #[cfg(all(
        feature = "pbs-bootstrap",
        target_os = "macos",
        target_arch = "aarch64",
        not(glue_python_macos_host)
    ))]
    {
        let _ = manifest;
        Err(unsupported(
            "the pinned Python boundary is not compiled; macOS arm64 builds require GLUE_PYTHON_INCLUDE_DIR to name the verified install-only header tree",
        ))
    }
    #[cfg(all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ))]
    {
        let component = manifest
            .components
            .get(&manifest.entrypoint)
            .ok_or_else(|| invalid("selected Python component does not exist"))?;
        let runtime = manifest
            .runtimes
            .get(&component.runtime)
            .ok_or_else(|| invalid("selected Python runtime does not exist"))?;
        let target = manifest
            .targets
            .get(&runtime.target)
            .ok_or_else(|| invalid("selected Python target does not exist"))?;
        validate_declaration(target)?;
        validate_host(target, &observe()?)
    }
    #[cfg(glue_python_macos_host)]
    {
        let component = manifest
            .components
            .get(&manifest.entrypoint)
            .ok_or_else(|| invalid("selected Python component does not exist"))?;
        let runtime = manifest
            .runtimes
            .get(&component.runtime)
            .ok_or_else(|| invalid("selected Python runtime does not exist"))?;
        let target = manifest
            .targets
            .get(&runtime.target)
            .ok_or_else(|| invalid("selected Python target does not exist"))?;
        validate_macos_declaration(target)?;
        validate_macos_host(target, &observe_macos()?)
    }
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )
))]
struct Host {
    kernel_version: String,
    glibc_version: String,
    page_size: u32,
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )
))]
fn validate_declaration(target: &TargetProfile) -> Result<(), ReadinessError> {
    if target.os != OperatingSystem::Linux || target.arch != Architecture::Aarch64 {
        return Err(unsupported(
            "the pinned Python target requires GNU Linux arm64",
        ));
    }
    let TargetAbi::Glibc { minimum_version } = &target.abi else {
        return Err(invalid("the pinned Python target requires a GNU libc ABI"));
    };
    numeric_version(&target.minimum_os_version)?;
    numeric_version(minimum_version)?;
    if target.page_sizes != std::collections::BTreeSet::from([4096]) {
        return Err(invalid(
            "the pinned Python target must declare exactly 4096-byte pages",
        ));
    }
    if !target.cpu_features.is_empty() {
        return Err(unsupported(
            "additional Python CPU feature requirements cannot be verified",
        ));
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    )
))]
fn validate_host(target: &TargetProfile, host: &Host) -> Result<(), ReadinessError> {
    validate_declaration(target)?;
    let TargetAbi::Glibc { minimum_version } = &target.abi else {
        unreachable!("validated GNU libc declaration")
    };
    if host.page_size != 4096 {
        return Err(unsupported(format!(
            "host page size {} differs from the required 4096 bytes",
            host.page_size
        )));
    }
    check_floor(
        &host.kernel_version,
        &target.minimum_os_version,
        "Linux kernel",
    )?;
    check_floor(&host.glibc_version, minimum_version, "GNU libc")
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ),
    glue_python_macos_host
))]
fn check_floor(actual: &str, minimum: &str, name: &str) -> Result<(), ReadinessError> {
    let observed = numeric_version(actual)
        .map_err(|_| unsupported(format!("cannot interpret host {name} version {actual:?}")))?;
    if observed < numeric_version(minimum)? {
        return Err(unsupported(format!(
            "host {name} version {actual} is below declared minimum {minimum}"
        )));
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ),
    glue_python_macos_host
))]
fn numeric_version(value: &str) -> Result<[u32; 4], ReadinessError> {
    let mut result = [0; 4];
    if value.len() > 64 {
        return Err(invalid("numeric version exceeds the bounded profile"));
    }
    for (index, part) in value.split('.').enumerate() {
        if index >= result.len() || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid(format!("invalid numeric version {value:?}")));
        }
        result[index] = part
            .parse()
            .map_err(|_| invalid(format!("invalid numeric version {value:?}")))?;
    }
    Ok(result)
}

#[cfg(all(
    feature = "pbs-bootstrap",
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu",
    glue_python_boundary
))]
fn observe() -> Result<Host, ReadinessError> {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname receives writable storage of its exact public layout and
    // initializes every field when it returns zero. This is a read-only query.
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return Err(unsupported(format!(
            "Linux kernel query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful uname initializes the storage and a terminated release
    // string. That storage remains live until the version has been copied.
    let value = unsafe { value.assume_init() };
    let release = unsafe { std::ffi::CStr::from_ptr(value.release.as_ptr()) }
        .to_str()
        .map_err(|_| unsupported("Linux kernel release is not UTF-8"))?;
    let kernel_version = release
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or("")
        .to_owned();
    // SAFETY: GNU libc returns a process-lifetime immutable terminated string,
    // with no arguments, ownership transfer or process configuration changes.
    let version = unsafe { libc::gnu_get_libc_version() };
    if version.is_null() {
        return Err(unsupported("GNU libc version query returned no value"));
    }
    // SAFETY: the pointer's lifetime/termination is guaranteed by that API.
    let glibc_version = unsafe { std::ffi::CStr::from_ptr(version) }
        .to_str()
        .map_err(|_| unsupported("GNU libc version is not UTF-8"))?
        .to_owned();
    // SAFETY: scalar query of a constant selector, with no Python or loader API.
    let page_size = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .map_err(|_| unsupported("host page size query failed"))?;
    Ok(Host {
        kernel_version,
        glibc_version,
        page_size,
    })
}

/// Observed facts of the running macOS host, compared with the declared
/// explicit-host startup target. Nothing here loads a library or opens the
/// declared installation.
#[cfg(any(test, glue_python_macos_host))]
struct MacosHost {
    os_version: String,
    page_size: u32,
}

#[cfg(any(test, glue_python_macos_host))]
fn validate_macos_declaration(target: &TargetProfile) -> Result<(), ReadinessError> {
    if target.os != OperatingSystem::Macos || target.arch != Architecture::Aarch64 {
        return Err(unsupported("the pinned Python target requires macOS arm64"));
    }
    if !matches!(target.abi, TargetAbi::Darwin) {
        return Err(invalid("the pinned Python target requires the Darwin ABI"));
    }
    numeric_version(&target.minimum_os_version)?;
    if target.page_sizes != std::collections::BTreeSet::from([crate::macos_host::PAGE_SIZE]) {
        return Err(invalid(format!(
            "the pinned Python target must declare exactly {}-byte pages",
            crate::macos_host::PAGE_SIZE
        )));
    }
    if !target.cpu_features.is_empty() {
        return Err(unsupported(
            "additional Python CPU feature requirements cannot be verified",
        ));
    }
    Ok(())
}

#[cfg(any(test, glue_python_macos_host))]
fn validate_macos_host(target: &TargetProfile, host: &MacosHost) -> Result<(), ReadinessError> {
    validate_macos_declaration(target)?;
    if host.page_size != crate::macos_host::PAGE_SIZE {
        return Err(unsupported(format!(
            "host page size {} differs from the required {} bytes",
            host.page_size,
            crate::macos_host::PAGE_SIZE
        )));
    }
    check_floor(&host.os_version, &target.minimum_os_version, "macOS")
}

#[cfg(glue_python_macos_host)]
fn observe_macos() -> Result<MacosHost, ReadinessError> {
    let mut buffer = [0u8; 64];
    let mut length = buffer.len();
    // SAFETY: sysctlbyname receives a terminated selector, writable storage of
    // `length` bytes together with that length's address, and no new value.
    // It is a read-only kernel query with no Python or loader API involved.
    if unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(unsupported(format!(
            "macOS version query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let os_version = buffer
        .get(..length)
        .and_then(|bytes| std::ffi::CStr::from_bytes_until_nul(bytes).ok())
        .ok_or_else(|| unsupported("macOS version query returned no terminated value"))?
        .to_str()
        .map_err(|_| unsupported("macOS version is not UTF-8"))?
        .to_owned();
    // SAFETY: scalar query of a constant selector, with no Python or loader API.
    let page_size = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .map_err(|_| unsupported("host page size query failed"))?;
    Ok(MacosHost {
        os_version,
        page_size,
    })
}

fn unsupported(message: impl Into<String>) -> ReadinessError {
    ReadinessError::Unsupported(message.into())
}

#[cfg(any(
    test,
    all(
        feature = "pbs-bootstrap",
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        glue_python_boundary
    ),
    glue_python_macos_host
))]
fn invalid(message: impl Into<String>) -> ReadinessError {
    ReadinessError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn target() -> TargetProfile {
        TargetProfile {
            os: OperatingSystem::Linux,
            arch: Architecture::Aarch64,
            minimum_os_version: "6.3.0".into(),
            abi: TargetAbi::Glibc {
                minimum_version: "2.17".into(),
            },
            page_sizes: BTreeSet::from([4096]),
            cpu_features: BTreeSet::new(),
        }
    }

    fn host() -> Host {
        Host {
            kernel_version: "6.18.4".into(),
            glibc_version: "2.36".into(),
            page_size: 4096,
        }
    }

    #[test]
    fn readiness_compares_numeric_versions_and_zero_padded_components() {
        let mut actual = host();
        actual.kernel_version = "6.3".into();
        actual.glibc_version = "2.17.0.0".into();
        assert!(validate_host(&target(), &actual).is_ok());
        actual.kernel_version = "6.10".into();
        assert!(validate_host(&target(), &actual).is_ok());
        actual.glibc_version = "2.9".into();
        assert!(matches!(
            validate_host(&target(), &actual),
            Err(ReadinessError::Unsupported(_))
        ));
    }

    #[test]
    fn readiness_rejects_insufficient_kernel_or_wrong_actual_page_size() {
        for (version, page_size) in [("6.2.99", 4096), ("6.18", 16384), ("6.18", 0)] {
            let actual = Host {
                kernel_version: version.into(),
                page_size,
                ..host()
            };
            assert!(matches!(
                validate_host(&target(), &actual),
                Err(ReadinessError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn readiness_rejects_malformed_or_overflowing_versions() {
        for version in [
            "",
            ".1",
            "1.",
            "1..2",
            "1.2.3.4.5",
            "-1",
            "1a",
            "4294967296",
        ] {
            assert!(matches!(
                numeric_version(version),
                Err(ReadinessError::Invalid(_))
            ));
            assert!(matches!(
                check_floor(version, "6.3", "Linux kernel"),
                Err(ReadinessError::Unsupported(_))
            ));
            assert!(matches!(
                check_floor("6.18", version, "Linux kernel"),
                Err(ReadinessError::Invalid(_))
            ));
        }
        assert!(numeric_version(&"1".repeat(65)).is_err());
    }

    fn macos_target() -> TargetProfile {
        TargetProfile {
            os: OperatingSystem::Macos,
            arch: Architecture::Aarch64,
            minimum_os_version: "26.7".into(),
            abi: TargetAbi::Darwin,
            page_sizes: BTreeSet::from([16384]),
            cpu_features: BTreeSet::new(),
        }
    }

    fn macos_host() -> MacosHost {
        MacosHost {
            os_version: "26.7".into(),
            page_size: 16384,
        }
    }

    #[test]
    fn macos_readiness_requires_the_exact_darwin_arm64_declaration() {
        assert!(validate_macos_host(&macos_target(), &macos_host()).is_ok());
        let mut declared = macos_target();
        declared.os = OperatingSystem::Linux;
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Unsupported(_))
        ));
        let mut declared = macos_target();
        declared.arch = Architecture::X86_64;
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Unsupported(_))
        ));
        let mut declared = macos_target();
        declared.abi = TargetAbi::Glibc {
            minimum_version: "2.36".into(),
        };
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Invalid(_))
        ));
        let mut declared = macos_target();
        declared.page_sizes.insert(4096);
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Invalid(_))
        ));
        let mut declared = macos_target();
        declared.page_sizes = BTreeSet::from([4096]);
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Invalid(_))
        ));
        let mut declared = macos_target();
        declared.cpu_features.insert("unknown".into());
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Unsupported(_))
        ));
        let mut declared = macos_target();
        declared.minimum_os_version = "26.7-beta".into();
        assert!(matches!(
            validate_macos_host(&declared, &macos_host()),
            Err(ReadinessError::Invalid(_))
        ));
        // Each cell reports the other cell's declaration as unsupported, not invalid.
        assert!(matches!(
            validate_macos_host(&target(), &macos_host()),
            Err(ReadinessError::Unsupported(_))
        ));
        assert!(matches!(
            validate_host(&macos_target(), &host()),
            Err(ReadinessError::Unsupported(_))
        ));
    }

    #[test]
    fn macos_readiness_compares_the_observed_version_and_page_size() {
        for version in ["26.7", "26.7.1", "26.10", "27.0"] {
            let actual = MacosHost {
                os_version: version.into(),
                page_size: 16384,
            };
            assert!(
                validate_macos_host(&macos_target(), &actual).is_ok(),
                "{version}"
            );
        }
        for (version, page_size) in [
            ("26.6", 16384),
            ("26", 16384),
            ("25.9.9", 16384),
            ("Version 26.7", 16384),
            ("", 16384),
            ("26.7", 4096),
            ("26.7", 0),
        ] {
            let actual = MacosHost {
                os_version: version.into(),
                page_size,
            };
            assert!(
                matches!(
                    validate_macos_host(&macos_target(), &actual),
                    Err(ReadinessError::Unsupported(_))
                ),
                "{version} {page_size}"
            );
        }
    }

    #[test]
    #[cfg(glue_python_macos_host)]
    fn this_macos_cell_is_ready_for_the_explicit_host_startup_profile_only() {
        use glue_format::{Compression, ResourceSpec};
        use std::collections::BTreeMap;

        let observed = observe_macos().unwrap();
        assert_eq!(observed.page_size, 16384);
        assert!(numeric_version(&observed.os_version).is_ok());
        let config = crate::macos_host::Config::parse("/pinned macOS Python").unwrap();
        let manifest = crate::macos_host::profile_manifest(&config).unwrap();
        readiness(&manifest).unwrap();
        let mut above = manifest.clone();
        above
            .targets
            .get_mut(crate::macos_host::TARGET)
            .unwrap()
            .minimum_os_version = "4294967295.0".into();
        assert!(matches!(
            readiness(&above),
            Err(ReadinessError::Unsupported(_))
        ));
        let linux = crate::profile_manifest(
            BTreeMap::from([(
                crate::APP.into(),
                ResourceSpec {
                    size: crate::HOST_APP.len() as u64,
                    sha256: crate::digest(crate::HOST_APP),
                    compression: Compression::Stored,
                },
            )]),
            Some(&crate::host::Config::parse("/pinned Linux Python").unwrap()),
        )
        .unwrap();
        assert!(matches!(
            readiness(&linux),
            Err(ReadinessError::Unsupported(_))
        ));
    }

    #[test]
    fn readiness_requires_the_exact_gnu_arm64_declaration() {
        let mut declared = target();
        declared.os = OperatingSystem::Macos;
        assert!(matches!(
            validate_host(&declared, &host()),
            Err(ReadinessError::Unsupported(_))
        ));
        let mut declared = target();
        declared.arch = Architecture::X86_64;
        assert!(matches!(
            validate_host(&declared, &host()),
            Err(ReadinessError::Unsupported(_))
        ));
        let mut declared = target();
        declared.abi = TargetAbi::Musl {
            minimum_version: "1.2".into(),
        };
        assert!(matches!(
            validate_host(&declared, &host()),
            Err(ReadinessError::Invalid(_))
        ));
        let mut declared = target();
        declared.page_sizes.insert(16384);
        assert!(matches!(
            validate_host(&declared, &host()),
            Err(ReadinessError::Invalid(_))
        ));
        let mut declared = target();
        declared.cpu_features.insert("unknown".into());
        assert!(matches!(
            validate_host(&declared, &host()),
            Err(ReadinessError::Unsupported(_))
        ));
    }
}
