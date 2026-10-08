//! Unsafe boundary for this controlled glibc fixture. No general symbol API is exposed.

use super::{ProbeResult, failure};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    mem::ManuallyDrop,
    os::fd::{AsRawFd, FromRawFd},
    ptr::NonNull,
};

const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub(super) struct Report {
    pub dependency_seals: libc::c_int,
    pub module_seals: libc::c_int,
}

pub(super) fn execute(dependency: &[u8], module: &[u8]) -> ProbeResult<Report> {
    if !cfg!(target_env = "gnu") {
        return Err(failure(
            "this controlled fixture requires the glibc target environment",
        ));
    }
    // Require the declared page-size profile before any constructor executes.
    // SAFETY: sysconf takes a defined constant and returns a scalar value.
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
        return Err(failure(
            "this controlled fixture declares a 4096-byte page-size profile",
        ));
    }
    let dependency = SealedImage::new(c"glue-probe-dependency", dependency)?;
    let module = SealedImage::new(c"glue-probe-module", module)?;
    let dependency = dependency.load(libc::RTLD_NOW | libc::RTLD_GLOBAL)?;
    let module = module.load(libc::RTLD_NOW | libc::RTLD_LOCAL)?;
    let input = c"archive";
    let answer = module.answer(input)?;
    let data = module.data()?;
    let constructors = module.constructor_count()?;
    if answer != 42 || data != 7 || constructors != 1 {
        return Err(failure(format!(
            "fixture observed answer={answer} data={data} constructors={constructors}; expected 42/7/1"
        )));
    }
    module.reopen()?;
    if module.constructor_count()? != 1 {
        return Err(failure("reopening the same image repeated its constructor"));
    }
    Ok(Report {
        dependency_seals: dependency.seals,
        module_seals: module.seals,
    })
}

struct SealedImage {
    file: File,
    seals: libc::c_int,
}

impl SealedImage {
    fn new(name: &CStr, bytes: &[u8]) -> ProbeResult<Self> {
        // SAFETY: name is NUL-terminated and live; flags request the Linux memfd
        // interface directly. Unsupported kernel/policy failures are reported.
        let fd = unsafe {
            libc::memfd_create(
                name.as_ptr(),
                libc::MFD_EXEC | libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(failure(format!(
                "memfd_create(MFD_EXEC|MFD_CLOEXEC|MFD_ALLOW_SEALING): {error}; no fallback exists"
            )));
        }
        // SAFETY: a successful memfd_create returned a new descriptor exclusively
        // owned here. File assumes its ownership exactly once.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        // SAFETY: file owns a live memfd and this fcntl command takes an integer
        // seal mask. No writable mappings have been established.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } < 0 {
            let error = std::io::Error::last_os_error();
            return Err(failure(format!(
                "F_ADD_SEALS({REQUIRED_SEALS:#x}): {error}"
            )));
        }
        // SAFETY: file owns a live descriptor; F_GET_SEALS takes no extra argument.
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 {
            let error = std::io::Error::last_os_error();
            return Err(failure(format!("F_GET_SEALS: {error}")));
        }
        if seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err(failure("memfd did not retain all requested seals"));
        }
        Ok(Self { file, seals })
    }

    fn load(self, flags: libc::c_int) -> ProbeResult<LoadedImage> {
        let path = descriptor_path(self.file.as_raw_fd())?;
        // SAFETY: dlopen receives a live NUL-terminated descriptor path and valid
        // flags. Only the already-verified controlled C fixtures are executed.
        let handle = unsafe { libc::dlopen(path.as_ptr(), flags) };
        let handle = NonNull::new(handle).ok_or_else(|| failure(loader_error("dlopen")))?;
        Ok(LoadedImage {
            file: ManuallyDrop::new(self.file),
            handle,
            seals: self.seals,
        })
    }
}

// Loaded handles and descriptors intentionally stay pinned until process exit,
// including error exits. There is no dlclose or descriptor-closing Drop path.
struct LoadedImage {
    file: ManuallyDrop<File>,
    handle: NonNull<libc::c_void>,
    seals: libc::c_int,
}

impl LoadedImage {
    fn symbol(&self, name: &CStr) -> ProbeResult<*mut libc::c_void> {
        // SAFETY: clearing the calling thread's loader error takes no arguments.
        unsafe {
            libc::dlerror();
        }
        // SAFETY: the pinned OS-owned handle is valid; name is NUL-terminated.
        let pointer = unsafe { libc::dlsym(self.handle.as_ptr(), name.as_ptr()) };
        // SAFETY: dlerror returns a thread-local string or NULL. Copy it before
        // the next loader call can invalidate it.
        let error = unsafe { libc::dlerror() };
        if !error.is_null() {
            // SAFETY: the non-NULL loader error points to its NUL-terminated text.
            return Err(failure(
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
        if pointer.is_null() {
            return Err(failure("a fixed fixture symbol resolved to NULL"));
        }
        Ok(pointer)
    }

    fn answer(&self, input: &CStr) -> ProbeResult<libc::c_int> {
        type Answer = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
        // SAFETY: this fixed export in module.c has exactly the declared C ABI.
        // The function is called while its image and dependency remain pinned.
        let answer = unsafe {
            std::mem::transmute::<*mut libc::c_void, Answer>(self.symbol(c"glue_answer")?)
        };
        // SAFETY: input is a live NUL-terminated string; the controlled C function
        // retains no pointer and throws no exception across the Rust boundary.
        Ok(unsafe { answer(input.as_ptr()) })
    }

    fn data(&self) -> ProbeResult<libc::c_int> {
        let pointer = self.symbol(c"glue_probe_data")?.cast::<libc::c_int>();
        if !pointer.is_aligned() {
            return Err(failure("fixture data export is misaligned"));
        }
        // SAFETY: module.c defines this fixed export as a live initialized C int;
        // its loaded image is pinned and this single-threaded fixture never writes it.
        Ok(unsafe { pointer.read() })
    }

    fn constructor_count(&self) -> ProbeResult<libc::c_int> {
        type Count = unsafe extern "C" fn() -> libc::c_int;
        // SAFETY: this fixed export is the no-argument C int function in module.c.
        let count = unsafe {
            std::mem::transmute::<*mut libc::c_void, Count>(
                self.symbol(c"glue_probe_constructor_count")?,
            )
        };
        // SAFETY: the controlled function only reads its constructor counter;
        // it neither throws nor retains callbacks or borrowed pointers.
        Ok(unsafe { count() })
    }

    fn reopen(&self) -> ProbeResult<()> {
        let path = descriptor_path(self.file.as_raw_fd())?;
        // SAFETY: this is the exact live descriptor path used to load this pinned
        // image. The extra loader reference is also retained until process exit.
        let reopened = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if reopened.is_null() {
            return Err(failure(loader_error("repeated dlopen")));
        }
        if reopened != self.handle.as_ptr() {
            return Err(failure(
                "reopening the same memfd returned another loader handle",
            ));
        }
        Ok(())
    }
}

fn descriptor_path(fd: libc::c_int) -> ProbeResult<CString> {
    Ok(CString::new(format!("/proc/self/fd/{fd}"))?)
}

fn loader_error(operation: &str) -> String {
    // SAFETY: dlerror returns a NUL-terminated string valid until the next loader
    // operation on this thread. It is copied immediately, including error exits.
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        return format!("{operation} failed without a loader diagnostic");
    }
    // SAFETY: the pointer was checked and is the loader's NUL-terminated error text.
    format!(
        "{operation}: {}",
        unsafe { CStr::from_ptr(error) }.to_string_lossy()
    )
}
