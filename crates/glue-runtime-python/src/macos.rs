//! Explicit macOS arm64 host execution for the pinned stock PBS CPython 3.13.16
//! startup profile. dyld loads the verified installed library by its canonical
//! path; the archive supplies only the application, and no payload is written.
//!
//! This is a controlled host-provider observation on one cell. It does not map
//! a bundled runtime, admit native extensions, discover installations or
//! establish the macOS signing policy for distribution.
use super::macos_host;
use std::{
    ffi::{CStr, CString},
    fs::File,
    mem::ManuallyDrop,
    os::unix::fs::FileExt,
    sync::atomic::{AtomicBool, Ordering},
};

static ATTEMPTED: AtomicBool = AtomicBool::new(false);
const NAMES: [&str; 29] = [
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
    "PyImport_AppendInittab",
];
const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const MH_DYLIB: u32 = 6;
const LC_UUID: u32 = 0x1b;
const HEADER_BYTES: usize = 32;
const MAX_LOAD_COMMAND_BYTES: usize = 1024 * 1024;

#[repr(C)]
struct Api {
    abi_revision: u32,
    reserved: u32,
    symbols: [*mut libc::c_void; 29],
}
#[repr(C)]
struct BridgeResult {
    error: *mut libc::c_char,
    error_len: usize,
}
const _: () = {
    assert!(std::mem::size_of::<Api>() == 240);
    assert!(std::mem::size_of::<BridgeResult>() == 16);
};

unsafe extern "C" {
    fn glue_python_run_host(
        api: *const Api,
        prefix: *const libc::c_char,
        stdlib: *const libc::c_char,
        app: *const u8,
        app_len: usize,
        result: *mut BridgeResult,
    ) -> libc::c_int;
    fn glue_python_result_free(result: *mut BridgeResult);
    #[cfg(test)]
    fn glue_python_boundary_test_ownership() -> libc::c_int;
    #[cfg(test)]
    fn glue_python_boundary_test_host_paths() -> libc::c_int;
    // Public dyld image-table queries from <mach-o/dyld.h>, declared here
    // because the libc crate marks its wrappers deprecated.
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(index: u32) -> *const libc::c_char;
    fn _dyld_get_image_header(index: u32) -> *const libc::c_void;
}

pub(super) fn run_host(mut payload: macos_host::Payload, negative: bool) -> Result<(), String> {
    preflight()?;
    let verified = payload.config.verify()?;
    let prefix =
        CString::new(verified.config.prefix.as_str()).map_err(|_| "host prefix contains NUL")?;
    let stdlib =
        CString::new(verified.config.stdlib.as_str()).map_err(|_| "host stdlib contains NUL")?;
    let api = load_api(verified)?;
    if negative {
        payload
            .app
            .extend_from_slice(b"\nraise RuntimeError('intentional Python host app error')\n");
    }
    let mut result = BridgeResult {
        error: std::ptr::null_mut(),
        error_len: 0,
    };
    // SAFETY: canonical bounded ASCII paths and the verified application bytes
    // remain live for the synchronous C-owned initialization, execution and
    // finalization. No Python object or exception crosses into Rust.
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

fn preflight() -> Result<(), String> {
    for (name, value) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("DYLD_")) && !value.is_empty() {
            return Err(format!(
                "loader override {} is unsupported",
                name.to_string_lossy()
            ));
        }
    }
    // SAFETY: scalar OS query before any interpreter initialization.
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != libc::c_long::from(macos_host::PAGE_SIZE) {
        return Err("requires a 16384-byte host page size".into());
    }
    if ATTEMPTED.swap(true, Ordering::AcqRel) {
        return Err("only one host startup attempt is supported per process".into());
    }
    for name in NAMES {
        let key = CString::new(name).unwrap();
        // SAFETY: live C string, querying the existing global loader scope.
        if !unsafe { libc::dlsym(libc::RTLD_DEFAULT, key.as_ptr()) }.is_null() {
            return Err(format!("pre-existing Python API export {name}"));
        }
    }
    for image in images()?.iter().skip(1) {
        if !approved_os_image(image) {
            return Err(format!("unapproved preloaded image {image}"));
        }
    }
    Ok(())
}

/// The ordered dyld image table. Index 0 is the launcher itself.
fn images() -> Result<Vec<String>, String> {
    // SAFETY: dyld's image table queries are read-only; names are
    // process-lifetime terminated strings owned by dyld.
    let count = unsafe { _dyld_image_count() };
    let mut names = Vec::with_capacity(count as usize);
    for index in 0..count {
        let name = unsafe { _dyld_get_image_name(index) };
        if name.is_null() {
            return Err("dyld image without a name".into());
        }
        names.push(
            unsafe { CStr::from_ptr(name) }
                .to_str()
                .map_err(|_| "dyld image name is not UTF-8")?
                .to_owned(),
        );
    }
    Ok(names)
}

/// System libraries and frameworks come from the OS; everything else must be
/// the verified runtime library itself.
fn approved_os_image(name: &str) -> bool {
    name.starts_with("/usr/lib/") || name.starts_with("/System/Library/")
}

fn load_api(verified: macos_host::Verified) -> Result<Api, String> {
    let path = verified.config.library.clone();
    let expected = uuid_from_file(&verified.library)?;
    let before = images()?;
    let c_path = CString::new(path.as_str()).map_err(|_| "host library path contains NUL")?;
    // SAFETY: exact pinned stock image at a verified canonical path; dyld owns
    // the mapping. Eager binding and local scope; trusted native code.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(loader_error("dlopen"));
    }
    // Pin the verified descriptors and the loader handle for the process
    // lifetime, including all subsequent validation errors; CPython retains code.
    let _pinned = ManuallyDrop::new(verified);
    let after = images()?;
    if after.len() < before.len() || after[..before.len()] != before[..] {
        return Err("dyld image table changed unexpectedly".into());
    }
    let mut library_index = None;
    for (offset, name) in after[before.len()..].iter().enumerate() {
        if *name == path {
            if library_index.is_some() {
                return Err("verified library appears twice in the dyld image table".into());
            }
            library_index = Some(before.len() + offset);
        } else if !approved_os_image(name) {
            return Err(format!("unapproved runtime dependency {name}"));
        }
    }
    let index = library_index
        .ok_or("loaded library is absent from the dyld image table under its verified path")?;
    // SAFETY: the index is below the current image count; dyld returns the
    // mapped header of a live image that stays mapped for process life.
    let header = unsafe { _dyld_get_image_header(index as u32) };
    if header.is_null() {
        return Err("dyld image header unavailable".into());
    }
    let base = header as usize;
    if uuid_from_mapped(header.cast())? != expected {
        return Err("loaded library identity differs from the verified bytes".into());
    }
    let mut api = Api {
        abi_revision: 4,
        reserved: 0,
        symbols: [std::ptr::null_mut(); 29],
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
    Ok(api)
}

/// The LC_UUID of an arm64 Mach-O dylib from its header and load commands.
fn uuid_from_bytes(bytes: &[u8]) -> Result<[u8; 16], String> {
    let word = |offset: usize| -> Result<u32, String> {
        bytes
            .get(offset..offset + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| "Mach-O header is truncated".to_string())
    };
    if word(0)? != MH_MAGIC_64 || word(4)? != CPU_TYPE_ARM64 || word(12)? != MH_DYLIB {
        return Err("verified library is not an arm64 Mach-O dylib".into());
    }
    let commands = word(16)? as usize;
    let size = word(20)? as usize;
    if size > MAX_LOAD_COMMAND_BYTES || bytes.len() < HEADER_BYTES + size {
        return Err("Mach-O load commands exceed the header bytes".into());
    }
    let end = HEADER_BYTES + size;
    let mut offset = HEADER_BYTES;
    let mut uuid = None;
    for _ in 0..commands {
        let command = word(offset)?;
        let length = word(offset + 4)? as usize;
        if length < 8 || length % 8 != 0 || offset + length > end {
            return Err("invalid Mach-O load command".into());
        }
        if command == LC_UUID {
            if length != 24 || uuid.is_some() {
                return Err("invalid or repeated LC_UUID".into());
            }
            uuid = Some(bytes[offset + 8..offset + 24].try_into().unwrap());
        }
        offset += length;
    }
    if offset != end {
        return Err("Mach-O load commands do not fill their declared size".into());
    }
    uuid.ok_or_else(|| "Mach-O dylib has no LC_UUID".into())
}

fn command_bytes(head: &[u8; HEADER_BYTES]) -> Result<usize, String> {
    let size = u32::from_le_bytes(head[20..24].try_into().unwrap()) as usize;
    if size > MAX_LOAD_COMMAND_BYTES {
        return Err("Mach-O load commands exceed the bounded size".into());
    }
    Ok(size)
}

fn uuid_from_file(file: &File) -> Result<[u8; 16], String> {
    let mut head = [0u8; HEADER_BYTES];
    file.read_exact_at(&mut head, 0)
        .map_err(|error| format!("read verified library header: {error}"))?;
    let mut bytes = vec![0u8; HEADER_BYTES + command_bytes(&head)?];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|error| format!("read verified library load commands: {error}"))?;
    uuid_from_bytes(&bytes)
}

fn uuid_from_mapped(header: *const u8) -> Result<[u8; 16], String> {
    // SAFETY: dyld keeps the image's __TEXT segment, which begins with the
    // header and all load commands, mapped readable for process life. The
    // declared load-command size is bounded before the wider slice is formed.
    let head: [u8; HEADER_BYTES] = unsafe { std::slice::from_raw_parts(header, HEADER_BYTES) }
        .try_into()
        .unwrap();
    let size = command_bytes(&head)?;
    let bytes = unsafe { std::slice::from_raw_parts(header, HEADER_BYTES + size) };
    uuid_from_bytes(bytes)
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
        "C-owned Python host startup failed without a bounded diagnostic".into()
    };
    // SAFETY: initialized bridge result; only C frees its allocation.
    unsafe { glue_python_result_free(&mut result) };
    if status != 0 {
        return Err(error);
    }
    if negative {
        return Err("negative host fixture unexpectedly succeeded".into());
    }
    Ok(())
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
    use super::*;

    fn header(commands: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let body: Vec<u8> = commands
            .iter()
            .flat_map(|(command, payload)| {
                let mut entry = command.to_le_bytes().to_vec();
                entry.extend_from_slice(&((payload.len() + 8) as u32).to_le_bytes());
                entry.extend_from_slice(payload);
                entry
            })
            .collect();
        for word in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            MH_DYLIB,
            commands.len() as u32,
            body.len() as u32,
            0,
            0,
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn uuid_parsing_requires_one_well_formed_arm64_dylib_uuid() {
        let uuid = [7u8; 16];
        let good = header(&[(0x19, vec![0; 64]), (LC_UUID, uuid.to_vec())]);
        assert_eq!(uuid_from_bytes(&good).unwrap(), uuid);
        assert!(uuid_from_bytes(&header(&[(0x19, vec![0; 64])])).is_err());
        assert!(
            uuid_from_bytes(&header(&[
                (LC_UUID, uuid.to_vec()),
                (LC_UUID, uuid.to_vec())
            ]))
            .is_err()
        );
        assert!(uuid_from_bytes(&header(&[(LC_UUID, vec![1; 24])])).is_err());
        assert!(uuid_from_bytes(&good[..good.len() - 1]).is_err());
        let mut executable = good.clone();
        executable[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert!(uuid_from_bytes(&executable).is_err());
        let mut x86 = good.clone();
        x86[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        assert!(uuid_from_bytes(&x86).is_err());
        let mut oversized = good;
        oversized[20..24].copy_from_slice(&(MAX_LOAD_COMMAND_BYTES as u32 + 8).to_le_bytes());
        assert!(uuid_from_bytes(&oversized).is_err());
    }

    #[test]
    fn pinned_artifact_library_has_a_uuid_when_available() {
        let Some(path) = std::env::var_os("GLUE_PYTHON_MACOS_LIBRARY") else {
            return;
        };
        let file = File::open(path).unwrap();
        let uuid = uuid_from_file(&file).unwrap();
        assert_ne!(uuid, [0; 16]);
    }

    #[test]
    fn only_system_locations_are_approved_images() {
        assert!(approved_os_image("/usr/lib/libSystem.B.dylib"));
        assert!(approved_os_image(
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
        ));
        for name in [
            "/opt/homebrew/lib/libpython3.13.dylib",
            "/usr/local/lib/libz.dylib",
            "libSystem.B.dylib",
            "/Users/x/lib/libpython3.13.dylib",
        ] {
            assert!(!approved_os_image(name), "{name}");
        }
        assert!(images().unwrap().len() > 1);
    }

    #[test]
    fn c_boundary_self_tests_pass_on_macos() {
        // SAFETY: pure C ownership/metadata self-tests that never initialize Python.
        assert_eq!(unsafe { glue_python_boundary_test_ownership() }, 0);
        assert_eq!(unsafe { glue_python_boundary_test_host_paths() }, 0);
    }
}
