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
const NAMES: [&str; 28] = [
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
    "PyModule_New",
    "PyCFunction_NewEx",
    "PyImport_GetModuleDict",
    "PyDict_SetItemString",
    "PyBytes_FromStringAndSize",
    "PyErr_SetString",
    "PyExc_RuntimeError",
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
    symbols: [*mut libc::c_void; 28],
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
#[repr(C)]
struct ResourceReply {
    data: *mut u8,
    len: usize,
}
const _: () = {
    assert!(std::mem::size_of::<Api>() == 232);
    assert!(std::mem::size_of::<FrozenRecord>() == 24);
    assert!(std::mem::size_of::<BridgeResult>() == 16);
    assert!(std::mem::size_of::<ResourceReply>() == 16);
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
    fn glue_python_run_archive(
        api: *const Api,
        records: *const FrozenRecord,
        count: usize,
        prefix: *const libc::c_char,
        stdlib: *const libc::c_char,
        request: unsafe extern "C" fn(
            *mut libc::c_void,
            *const u8,
            usize,
            *mut ResourceReply,
        ) -> libc::c_int,
        release: unsafe extern "C" fn(*mut libc::c_void, *mut u8, usize),
        context: *mut libc::c_void,
        bootstrap: *const u8,
        bootstrap_len: usize,
        app: *const u8,
        app_len: usize,
        result: *mut BridgeResult,
    ) -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_ownership() -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_host_paths() -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_archive_callbacks() -> libc::c_int;
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
    let file = runtime_file(&payload.library, baseline)?;
    let api = load_api(file)?;
    invoke_frozen(&api, &mut payload, negative)
}

fn runtime_file(library: &[u8], baseline: Option<&Path>) -> Result<File, String> {
    if let Some(path) = baseline {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(LIBRARY_SIZE + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        check_library(&bytes)?;
        Ok(file)
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
        file.write_all(library).map_err(|e| e.to_string())?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: live memfd, integer seal mask, no writable mapping exists.
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0
            || unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } != seals
        {
            return Err("required four memfd seals unavailable; no fallback".into());
        }
        Ok(file)
    }
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
        abi_revision: 3,
        reserved: 0,
        symbols: [std::ptr::null_mut(); 28],
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

pub(super) fn run_imports(
    mut payload: import_profile::Payload,
    baseline: Option<&Path>,
    negative: bool,
) -> Result<(), String> {
    preflight()?;
    let api = load_api(runtime_file(&payload.library, baseline)?)?;
    let mut names = Vec::new();
    let mut codes = Vec::new();
    for module in &payload.bundle.modules {
        names.push(CString::new(module.name.as_str()).map_err(|_| "frozen name contains NUL")?);
        codes.push(module.decode_hex()?);
    }
    let records: Vec<_> = payload
        .bundle
        .modules
        .iter()
        .zip(&names)
        .zip(&codes)
        .map(|((module, name), code)| FrozenRecord {
            name: name.as_ptr(),
            code: code.as_ptr(),
            size: code.len() as i32,
            is_package: i32::from(module.is_package),
        })
        .collect();
    invoke_archive(
        &api,
        ArchiveStartup::Frozen(&records),
        ArchiveApplication {
            app: &mut payload.app,
            bootstrap: &payload.bootstrap,
            index: &mut payload.index,
        },
        negative,
    )
}

pub(super) fn run_host_imports(
    mut payload: host_import_profile::Payload,
    negative: bool,
) -> Result<(), String> {
    preflight()?;
    let verified = payload
        .config
        .verify_imports(&host_import_profile::source_specs()?)?;
    let prefix =
        CString::new(verified.config.prefix.as_str()).map_err(|_| "host prefix contains NUL")?;
    let stdlib =
        CString::new(verified.config.stdlib.as_str()).map_err(|_| "host stdlib contains NUL")?;
    // Partially moving the library pins it in load_api. The remaining verified
    // source/directory owners stay in this caller scope through finalization.
    let api = load_api(verified.library)?;
    invoke_archive(
        &api,
        ArchiveStartup::Host(&prefix, &stdlib),
        ArchiveApplication {
            app: &mut payload.app,
            bootstrap: &payload.bootstrap,
            index: &mut payload.index,
        },
        negative,
    )
}

enum ArchiveStartup<'a> {
    Frozen(&'a [FrozenRecord]),
    Host(&'a CStr, &'a CStr),
}

struct ArchiveApplication<'a> {
    app: &'a mut Vec<u8>,
    bootstrap: &'a [u8],
    index: &'a mut imports::Index,
}

fn invoke_archive(
    api: &Api,
    startup: ArchiveStartup<'_>,
    payload: ArchiveApplication<'_>,
    negative: bool,
) -> Result<(), String> {
    if negative {
        payload
            .app
            .extend_from_slice(b"\nraise RuntimeError('intentional Python archive app error')\n");
    }
    let mut result = BridgeResult {
        error: std::ptr::null_mut(),
        error_len: 0,
    };
    let (records, count, prefix, stdlib) = match startup {
        ArchiveStartup::Frozen(records) => (
            records.as_ptr(),
            records.len(),
            std::ptr::null(),
            std::ptr::null(),
        ),
        ArchiveStartup::Host(prefix, stdlib) => {
            (std::ptr::null(), 0, prefix.as_ptr(), stdlib.as_ptr())
        }
    };
    // SAFETY: all records, source and immutable resource context outlive this
    // synchronous call and finalization. C owns every Python API/object. Rust
    // callbacks catch panics and return buffers before C calls Python again.
    let status = unsafe {
        glue_python_run_archive(
            api,
            records,
            count,
            prefix,
            stdlib,
            resource_request,
            resource_release,
            (payload.index as *mut imports::Index).cast(),
            payload.bootstrap.as_ptr(),
            payload.bootstrap.len(),
            payload.app.as_ptr(),
            payload.app.len(),
            &mut result,
        )
    };
    finish_result(status, result, negative)
}

fn callback_outcome(action: impl FnOnce() -> Result<Vec<u8>, String>) -> (libc::c_int, Vec<u8>) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(Ok(bytes)) => (0, bytes),
        Ok(Err(error)) => (1, error.chars().take(4096).collect::<String>().into_bytes()),
        Err(payload) => {
            // An arbitrary panic payload can panic again in Drop. Leak it on
            // this exceptional path so its destructor cannot unwind into C.
            std::mem::forget(payload);
            (1, b"archive resource callback panicked".to_vec())
        }
    }
}

unsafe extern "C" fn resource_request(
    context: *mut libc::c_void,
    request: *const u8,
    request_len: usize,
    reply: *mut ResourceReply,
) -> libc::c_int {
    if context.is_null()
        || reply.is_null()
        || request_len > 4096
        || (request.is_null() && request_len != 0)
    {
        return 1;
    }
    // SAFETY: C supplies the live borrowed Index, bounded request slice and
    // fresh writable reply. Empty requests avoid constructing a NULL slice.
    let (status, bytes) = callback_outcome(|| {
        let index = unsafe { &*context.cast::<imports::Index>() };
        let request = if request_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(request, request_len) }
        };
        index.request(request)
    });
    let bytes = bytes.into_boxed_slice();
    let len = bytes.len();
    let data = Box::into_raw(bytes).cast::<u8>();
    // SAFETY: C owns this transferred allocation and releases it exactly once
    // with the same pointer/length, including empty allocations and errors.
    unsafe {
        reply.write(ResourceReply { data, len });
    }
    status
}

unsafe extern "C" fn resource_release(_: *mut libc::c_void, data: *mut u8, len: usize) {
    if !data.is_null() {
        // SAFETY: same owned Box<[u8]> allocation transferred by our request;
        // C copies the data first and releases once, before any Python call.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len)) });
    }
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
    #[test]
    fn c_copies_and_releases_archive_callback_buffers_before_python_calls() {
        // SAFETY: C-only callback ownership/control selftest; no Python calls.
        assert_eq!(
            unsafe { super::glue_python_boundary_test_archive_callbacks() },
            0
        );
    }
    #[test]
    fn resource_callback_contains_panics_and_transfers_binary_or_error_buffers() {
        use super::*;
        let (status, bytes) = callback_outcome(|| panic!("intentional callback panic"));
        assert_eq!(status, 1);
        assert_eq!(bytes, b"archive resource callback panicked");
        let mut index = imports::Index::new(
            "fixture",
            BTreeMap::from([("app/python/data.bin".into(), vec![0, 255])]),
        )
        .unwrap();
        for (request, expected_status) in [
            (b"read\tapp/python/data.bin".as_slice(), 0),
            (b"read\tapp/python/../data.bin".as_slice(), 1),
        ] {
            let mut reply = ResourceReply {
                data: std::ptr::null_mut(),
                len: 0,
            };
            // SAFETY: live local context/request/reply; exactly one matching free.
            let status = unsafe {
                resource_request(
                    (&mut index as *mut imports::Index).cast(),
                    request.as_ptr(),
                    request.len(),
                    &mut reply,
                )
            };
            assert_eq!(status, expected_status);
            assert!(!reply.data.is_null());
            if status == 0 {
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(reply.data, reply.len) },
                    [0, 255]
                );
            }
            unsafe { resource_release(std::ptr::null_mut(), reply.data, reply.len) };
        }
    }

    #[test]
    fn resource_callback_never_drops_a_panicking_panic_payload() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct DropPanic(Arc<AtomicUsize>);
        impl Drop for DropPanic {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("panic payload destructor");
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let (status, bytes) = super::callback_outcome(|| {
            std::panic::panic_any(DropPanic(Arc::clone(&drops)));
        });
        assert_eq!(status, 1);
        assert_eq!(bytes, b"archive resource callback panicked");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
}
