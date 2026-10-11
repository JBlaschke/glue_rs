//! Read-only prerequisites for the optional, pinned GNU Linux arm64 profile.
//! These queries never load Python, open host installations or claim the
//! process execution attempt. Legacy experiment entry points bypass them.

use glue_format::Manifest;
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
use glue_format::{Architecture, OperatingSystem, TargetAbi, TargetProfile};

#[derive(Debug)]
pub(crate) enum ReadinessError {
    Unsupported(String),
    #[cfg_attr(
        not(all(
            feature = "pbs-bootstrap",
            target_os = "linux",
            target_arch = "aarch64",
            target_env = "gnu",
            glue_python_boundary
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
    )
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
    )
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
    )
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
