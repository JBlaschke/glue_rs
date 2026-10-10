//! Exact-image experiment. GNU ld.so handles the stock image's TLS/relocations;
//! this does not extend the general native Lua ELF admission profile.
use super::*;
use std::{
    ffi::{CStr, CString},
    io::Write,
    mem::ManuallyDrop,
    os::fd::{AsRawFd, FromRawFd},
    sync::atomic::{AtomicBool, Ordering},
};

static ATTEMPTED: AtomicBool = AtomicBool::new(false);
const NAMES: [&str; 21] = [
    "Py_GetVersion",
    "Py_IsInitialized",
    "PyPreConfig_InitIsolatedConfig",
    "Py_PreInitialize",
    "PyConfig_InitIsolatedConfig",
    "PyConfig_SetString",
    "PyConfig_Clear",
    "Py_InitializeFromConfig",
    "PyStatus_Exception",
    "PyStatus_IsExit",
    "PyImport_AddModuleRef",
    "PyModule_GetDict",
    "PyRun_StringFlags",
    "Py_DecRef",
    "PyErr_GetRaisedException",
    "PyObject_Str",
    "PyUnicode_AsUTF8AndSize",
    "PyErr_Clear",
    "Py_FinalizeEx",
    "PyImport_FrozenModules",
    "PyWideStringList_Append",
];
const OS_LIBRARIES: [&str; 9] = [
    "libc.so.6",
    "libm.so.6",
    "libpthread.so.0",
    "librt.so.1",
    "libdl.so.2",
    "libutil.so.1",
    "ld-linux-aarch64.so.1",
    "libgcc_s.so.1",
    "linux-vdso.so.1",
];

#[repr(C)]
struct Api {
    abi_revision: u32,
    reserved: u32,
    symbols: [*mut libc::c_void; 21],
}
#[repr(C)]
struct FrozenRecord {
    name: *const libc::c_char,
    code: *const u8,
    size: i32,
    is_package: i32,
}
#[repr(C)]
struct BridgeResult {
    error: *mut libc::c_char,
    error_len: usize,
}
const _: () = {
    assert!(std::mem::size_of::<Api>() == 176);
    assert!(std::mem::size_of::<FrozenRecord>() == 24);
    assert!(std::mem::size_of::<BridgeResult>() == 16);
};
unsafe extern "C" {
    fn glue_python_run(
        api: *const Api,
        records: *const FrozenRecord,
        count: usize,
        app: *const u8,
        app_len: usize,
        result: *mut BridgeResult,
    ) -> libc::c_int;
    fn glue_python_result_free(result: *mut BridgeResult);
    fn glue_python_run_host(
        api: *const Api,
        prefix: *const libc::c_char,
        stdlib: *const libc::c_char,
        app: *const u8,
        app_len: usize,
        result: *mut BridgeResult,
    ) -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_ownership() -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_host_paths() -> libc::c_int;
}

fn preflight() -> Result<(), String> {
    for name in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_BIND_NOT",
        "LD_DYNAMIC_WEAK",
        "LD_HWCAP_MASK",
        "GLIBC_TUNABLES",
    ] {
        if std::env::var_os(name).is_some_and(|v| !v.is_empty()) {
            return Err(format!("loader override {name} is unsupported"));
        }
    }
    // SAFETY: scalar OS query before any interpreter initialization.
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
        return Err("requires a 4096-byte host page size".into());
    }
    if ATTEMPTED.swap(true, Ordering::AcqRel) {
        return Err("only one bootstrap attempt is supported per process".into());
    }
    check_images(None)?;
    for name in NAMES {
        let key = CString::new(name).unwrap();
        // SAFETY: live C string, querying the existing global loader scope.
        if !unsafe { libc::dlsym(libc::RTLD_DEFAULT, key.as_ptr()) }.is_null() {
            return Err(format!("pre-existing Python API export {name}"));
        }
    }
    Ok(())
}

pub(super) fn run(
    mut payload: Payload,
    baseline: Option<&Path>,
    negative: Option<&str>,
) -> Result<(), String> {
    preflight()?;
    let file = if let Some(path) = baseline {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(LIBRARY_SIZE + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        check_library(&bytes)?;
        file
    } else {
        let name = CString::new("glue-python-libpython3.13.so.1.0").unwrap();
        // SAFETY: terminated name and explicit Linux executable memfd flags.
        let fd = unsafe {
            libc::memfd_create(
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_EXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "memfd_create(MFD_EXEC): {}; no fallback",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: new descriptor is exclusively owned by this File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&payload.library)
            .map_err(|e| e.to_string())?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: live memfd, integer seal mask, no writable mapping exists.
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0
            || unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } != seals
        {
            return Err("required four memfd seals unavailable; no fallback".into());
        }
        file
    };
    let api = load_api(file)?;
    invoke_frozen(&api, &mut payload, negative)
}

fn load_api(file: File) -> Result<Api, String> {
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    // SAFETY: exact pinned stock image, immutable sealed fd (or read-only pinned
    // comparison input); trusted native code. Eager system-loader relocation.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(loader_error("dlopen"));
    }
    // Pin the descriptor and loader handle for the process lifetime, including
    // all subsequent validation errors. CPython/native finalizers retain code.
    let _pinned = ManuallyDrop::new(file);
    let mut link: *mut LinkMap = std::ptr::null_mut();
    // SAFETY: GNU loader writes its link_map pointer for the live handle.
    if unsafe {
        libc::dlinfo(
            handle,
            libc::RTLD_DI_LINKMAP,
            (&mut link as *mut *mut LinkMap).cast(),
        )
    } != 0
        || link.is_null()
    {
        return Err(loader_error("dlinfo"));
    }
    // SAFETY: live loader-owned link_map prefix.
    let base = unsafe { (*link).address };
    let mut api = Api {
        abi_revision: 2,
        reserved: 0,
        symbols: [std::ptr::null_mut(); 21],
    };
    for (slot, name) in api.symbols.iter_mut().zip(NAMES) {
        let key = CString::new(name).unwrap();
        // SAFETY: live loader handle and symbol string; error state is cleared.
        unsafe { libc::dlerror() };
        let address = unsafe { libc::dlsym(handle, key.as_ptr()) };
        if address.is_null() {
            return Err(loader_error(name));
        }
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: initialized writable metadata and live resolved address.
        if unsafe { libc::dladdr(address.cast_const(), &mut info) } == 0
            || info.dli_fbase as usize != base
        {
            return Err(format!("Python API ownership differs: {name}"));
        }
        *slot = address;
    }
    check_images(Some(base))?;
    Ok(api)
}

fn invoke_frozen(api: &Api, payload: &mut Payload, negative: Option<&str>) -> Result<(), String> {
    let mut names = Vec::new();
    let mut codes = Vec::new();
    let mut packages = Vec::new();
    for module in &payload.bundle.modules {
        if negative == Some("missing-encodings") && module.name == "encodings" {
            continue;
        }
        names.push(CString::new(module.name.as_str()).map_err(|_| "frozen name contains NUL")?);
        codes.push(
            if negative == Some("bad-bytecode") && module.name == "encodings" {
                vec![0xff]
            } else {
                module.decode_hex()?
            },
        );
        packages.push(i32::from(module.is_package));
    }
    let records: Vec<_> = names
        .iter()
        .zip(&codes)
        .zip(packages)
        .map(|((name, code), is_package)| FrozenRecord {
            name: name.as_ptr(),
            code: code.as_ptr(),
            size: code.len() as i32,
            is_package,
        })
        .collect();
    if negative == Some("app-error") {
        payload
            .app
            .extend_from_slice(b"\nraise RuntimeError('intentional Python bootstrap app error')\n");
    }
    let mut result = BridgeResult {
        error: std::ptr::null_mut(),
        error_len: 0,
    };
    // SAFETY: all byte/name slices remain live for the synchronous C-owned
    // interpreter call. No Python pointer or exception unwinds through Rust;
    // C owns PyConfig, PyObjects, table copies and all finalization.
    let status = unsafe {
        glue_python_run(
            api,
            records.as_ptr(),
            records.len(),
            payload.app.as_ptr(),
            payload.app.len(),
            &mut result,
        )
    };
    finish_result(status, result, negative.is_some())
}

pub(super) fn run_host(mut payload: HostPayload, negative: bool) -> Result<(), String> {
    preflight()?;
    let verified = payload.config.verify()?;
    let prefix =
        CString::new(verified.config.prefix.as_str()).map_err(|_| "host prefix contains NUL")?;
    let stdlib =
        CString::new(verified.config.stdlib.as_str()).map_err(|_| "host stdlib contains NUL")?;
    // The remaining verified source/directory descriptors stay owned until the
    // end of this scope; load_api pins the selected library descriptor/handle.
    let api = load_api(verified.library)?;
    if negative {
        payload
            .app
            .extend_from_slice(b"\nraise RuntimeError('intentional Python host app error')\n");
    }
    let mut result = BridgeResult {
        error: std::ptr::null_mut(),
        error_len: 0,
    };
    // SAFETY: canonical bounded ASCII paths and verified source remain live for
    // the synchronous C-owned host initialization, execution and finalization.
    let status = unsafe {
        glue_python_run_host(
            &api,
            prefix.as_ptr(),
            stdlib.as_ptr(),
            payload.app.as_ptr(),
            payload.app.len(),
            &mut result,
        )
    };
    finish_result(status, result, negative)
}

fn finish_result(
    status: libc::c_int,
    mut result: BridgeResult,
    negative: bool,
) -> Result<(), String> {
    let error = if !result.error.is_null() && result.error_len <= 16 * 1024 {
        // SAFETY: bridge contract owns a live error_len-byte buffer until free.
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(result.error.cast::<u8>(), result.error_len)
        })
        .into_owned()
    } else {
        "C-owned Python bootstrap failed without a bounded diagnostic".into()
    };
    // SAFETY: initialized bridge result; only C frees its allocation.
    unsafe { glue_python_result_free(&mut result) };
    if status != 0 {
        return Err(error);
    }
    if negative {
        return Err("negative bootstrap fixture unexpectedly succeeded".into());
    }
    Ok(())
}

#[repr(C)]
struct LinkMap {
    address: usize,
}

struct ImageCheck {
    runtime_base: Option<usize>,
    invalid: bool,
}
fn check_images(runtime_base: Option<usize>) -> Result<(), String> {
    let mut check = ImageCheck {
        runtime_base,
        invalid: false,
    };
    // SAFETY: synchronous loader traversal, callback only inspects loader-owned
    // metadata; data remains live and callback performs no panicking operation.
    let status = unsafe {
        libc::dl_iterate_phdr(Some(image_callback), (&mut check as *mut ImageCheck).cast())
    };
    if check.invalid || status != 0 {
        Err("unapproved preloaded image or runtime dependency".into())
    } else {
        Ok(())
    }
}
unsafe extern "C" fn image_callback(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut libc::c_void,
) -> libc::c_int {
    if info.is_null() || size < std::mem::size_of::<libc::dl_phdr_info>() || data.is_null() {
        return 1;
    }
    // SAFETY: dl_iterate_phdr provides loader-owned metadata and caller data.
    let info = unsafe { &*info };
    let check = unsafe { &mut *data.cast::<ImageCheck>() };
    if info.dlpi_name.is_null() {
        check.invalid = true;
        return 1;
    }
    let bytes = unsafe { CStr::from_ptr(info.dlpi_name) }.to_bytes();
    if bytes.is_empty() || check.runtime_base == Some(info.dlpi_addr as usize) {
        return 0;
    }
    let name = bytes.rsplit(|b| *b == b'/').next().unwrap_or(bytes);
    let approved = OS_LIBRARIES.iter().any(|n| n.as_bytes() == name)
        && (bytes == b"linux-vdso.so.1"
            || bytes.starts_with(b"/lib/")
            || bytes.starts_with(b"/usr/lib/"));
    if !approved {
        check.invalid = true;
        return 1;
    }
    0
}
fn loader_error(context: &str) -> String {
    // SAFETY: dlerror returns a terminated, thread-local loader diagnostic.
    let ptr = unsafe { libc::dlerror() };
    if ptr.is_null() {
        format!("{context}: loader operation failed")
    } else {
        format!(
            "{context}: {}",
            unsafe { CStr::from_ptr(ptr) }.to_string_lossy()
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn c_owns_frozen_records_and_error_buffers() {
        // SAFETY: C-only ownership self-test does not initialize Python or
        // invoke dynamic API addresses; all allocations are local and released.
        assert_eq!(unsafe { super::glue_python_boundary_test_ownership() }, 0);
    }

    #[test]
    fn c_owns_host_paths_and_rejects_invalid_configuration() {
        // SAFETY: C-only validation/ownership self-test; no Python calls.
        assert_eq!(unsafe { super::glue_python_boundary_test_host_paths() }, 0);
    }
}
