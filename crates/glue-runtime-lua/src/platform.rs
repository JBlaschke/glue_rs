//! Narrow, read-only platform prerequisite queries for the linked Lua profile.

use super::{CapabilityError, unsupported};
use glue_format::{Architecture, OperatingSystem};

pub(super) struct Host {
    pub(super) os: OperatingSystem,
    pub(super) arch: Architecture,
    pub(super) os_version: String,
    pub(super) glibc_version: Option<String>,
    pub(super) page_size: u32,
}

pub(super) fn observe() -> Result<Host, CapabilityError> {
    #[cfg(target_arch = "aarch64")]
    let arch = Architecture::Aarch64;
    #[cfg(target_arch = "x86_64")]
    let arch = Architecture::X86_64;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    return Err(unsupported("this architecture has not been observed"));

    #[cfg(all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "macos"
    ))]
    return Ok(Host {
        os: OperatingSystem::Macos,
        arch,
        os_version: macos_version()?,
        glibc_version: None,
        page_size: page_size()?,
    });
    #[cfg(all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "linux",
        target_env = "gnu"
    ))]
    return Ok(Host {
        os: OperatingSystem::Linux,
        arch,
        os_version: linux_version()?,
        glibc_version: Some(glibc_version()?),
        page_size: page_size()?,
    });
    #[cfg(all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))
    ))]
    {
        let _ = arch;
        Err(unsupported(
            "only macOS Darwin and GNU Linux linked Lua profiles have been observed",
        ))
    }
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn page_size() -> Result<u32, CapabilityError> {
    // SAFETY: sysconf takes a constant query selector and no pointers. It does
    // not modify process configuration or filesystem state.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let value = u32::try_from(value).map_err(|_| unsupported("host page size query failed"))?;
    if value == 0 || !value.is_power_of_two() {
        return Err(unsupported("host page size query returned an invalid size"));
    }
    Ok(value)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn linux_version() -> Result<String, CapabilityError> {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: value points to writable storage of exactly the utsname layout;
    // uname initializes that storage only when it returns success.
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return Err(unsupported(format!(
            "Linux kernel query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful uname initialized every field, including a terminated
    // release string. Its storage remains live for the entire CStr conversion.
    let value = unsafe { value.assume_init() };
    let release = unsafe { std::ffi::CStr::from_ptr(value.release.as_ptr()) }
        .to_str()
        .map_err(|_| unsupported("Linux kernel release is not UTF-8"))?;
    let numeric = release
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .next()
        .unwrap_or("");
    if numeric.is_empty() {
        return Err(unsupported("Linux kernel release has no numeric version"));
    }
    Ok(numeric.to_owned())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn glibc_version() -> Result<String, CapabilityError> {
    // SAFETY: GNU libc returns a process-lifetime pointer to an immutable,
    // NUL-terminated version string; it takes no inputs and changes no state.
    let pointer = unsafe { libc::gnu_get_libc_version() };
    if pointer.is_null() {
        return Err(unsupported("GNU libc version query returned no value"));
    }
    // SAFETY: the non-null pointer has the lifetime and termination guaranteed
    // by gnu_get_libc_version above, and is copied before returning.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| unsupported("GNU libc version is not UTF-8"))
}

#[cfg(target_os = "macos")]
fn macos_version() -> Result<String, CapabilityError> {
    let mut buffer = [0u8; 128];
    let mut length = buffer.len();
    // SAFETY: the query name is a terminated static string. The output pointer
    // addresses buffer's writable bytes and length reports its actual capacity;
    // a null new-value pointer with length zero makes this a read-only query.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length == 0 || length > buffer.len() {
        return Err(unsupported(format!(
            "macOS product version query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    std::ffi::CStr::from_bytes_until_nul(&buffer[..length])
        .map_err(|_| unsupported("macOS product version is not terminated"))?
        .to_str()
        .map(str::to_owned)
        .map_err(|_| unsupported("macOS product version is not UTF-8"))
}
