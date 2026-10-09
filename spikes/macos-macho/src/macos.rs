//! Private, single-use mapping experiment. No dyld payload API or filesystem writes.

use crate::{ProbeResult, failure, macho, validate_closure};
use std::{
    ffi::CStr,
    io,
    sync::atomic::{AtomicBool, Ordering},
};

const PAGE: usize = 16_384;
const MAX_ARENA: usize = 64 * 1024 * 1024;
static ATTEMPTED: AtomicBool = AtomicBool::new(false);

// CS_OPS_STATUS, CS_VALID and CS_RUNTIME come from Apple's published XNU
// bsd/sys/codesign.h and osfmk/kern/cs_blobs.h. This observes the process flags;
// it does not authenticate archive images or establish distribution signing.
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        operation: u32,
        output: *mut libc::c_void,
        size: usize,
    ) -> libc::c_int;
    fn sys_icache_invalidate(start: *mut libc::c_void, length: usize);
}

pub struct Report {
    pub answer: i32,
    pub data: i32,
    pub constructors: i32,
    pub pid: i32,
}

struct Arena {
    base: *mut u8,
    size: usize,
}
impl Drop for Arena {
    fn drop(&mut self) {
        // No native code has run while this owner can be dropped. We pin the
        // arena before the first constructor, including every later failure.
        unsafe {
            libc::munmap(self.base.cast(), self.size);
        }
    }
}

struct Writing;
impl Writing {
    fn begin() -> Self {
        // This probe is single-threaded and performs no foreign callbacks while
        // writable. Rust/system implementation code lives outside the JIT arena.
        unsafe {
            libc::pthread_jit_write_protect_np(0);
        }
        Self
    }
}
impl Drop for Writing {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_jit_write_protect_np(1);
        }
    }
}

pub fn execute(dependency: &[u8], module: &[u8]) -> ProbeResult<Report> {
    // Parse/validate the entire graph before any OS acquisition or mapping.
    let images = [
        macho::parse(dependency).map_err(|e| failure(&e))?,
        macho::parse(module).map_err(|e| failure(&e))?,
    ];
    let sources = [dependency, module];
    validate_closure(&images)?;
    let sizes = [
        usize::try_from(images[0].vm_size)?,
        usize::try_from(images[1].vm_size)?,
    ];
    let size = sizes[0]
        .checked_add(sizes[1])
        .ok_or_else(|| failure("arena size overflow"))?;
    if size == 0 || size > MAX_ARENA || size % PAGE != 0 {
        return Err(failure("unsupported arena size or page layout"));
    }
    let offsets = [0, sizes[0]];
    let mut version = [0u8; 64];
    let mut version_size = version.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            version.as_mut_ptr().cast(),
            &mut version_size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || version_size == 0
        || version_size > version.len()
        || version[version_size - 1] != 0
    {
        return Err(failure("cannot establish the observed macOS version"));
    }
    let version = std::str::from_utf8(&version[..version_size - 1])?;
    if version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_none_or(|major| major < 13)
    {
        return Err(failure("fixture requires macOS 13 or newer"));
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page != PAGE as i64 || unsafe { libc::pthread_jit_write_protect_supported_np() } != 1 {
        return Err(failure(
            "require 16 KiB pages and per-thread JIT write protection",
        ));
    }
    if std::env::vars_os().any(|(key, _)| key.as_encoded_bytes().starts_with(b"DYLD_")) {
        return Err(failure("DYLD environment overrides are unsupported"));
    }
    let mut flags = 0u32;
    if unsafe { csops(libc::getpid(), 0, (&mut flags as *mut u32).cast(), 4) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if flags & 0x10001 != 0x10001 || flags & 0x10000004 != 0 {
        return Err(failure(
            "require valid signed hardened-runtime executable without debugger access",
        ));
    }
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Err(failure("only one mapping attempt per process is supported"));
    }
    let getpid = system_getpid()?;
    // MAP_JIT is the sole executable allocation. Data/metadata pages are then
    // replaced with ordinary anonymous mappings inside this exclusively owned
    // range. MAP_FIXED addresses can never come from archive input directly.
    // JIT pages retain VM-level RWX and use Apple's per-thread W^X mechanism;
    // mprotect cannot demote them on the observed arm64 kernel.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(io::Error::last_os_error().into());
    }
    let arena = Arena {
        base: base.cast(),
        size,
    };
    if arena.base as usize % PAGE != 0 {
        return Err(failure("JIT arena is not page-aligned"));
    }
    for (index, image) in images.iter().enumerate() {
        for segment in &image.segments {
            if segment.initial_protection & 4 == 0 {
                let at = offsets[index]
                    .checked_add(usize::try_from(segment.vm_address)?)
                    .ok_or_else(|| failure("segment offset overflow"))?;
                let length = usize::try_from(segment.vm_size)?;
                owned_range(at, length, size)?;
                if at % PAGE != 0 || length == 0 || length % PAGE != 0 {
                    return Err(failure("normal mappings require complete owned pages"));
                }
                let target = unsafe { arena.base.add(at) };
                let mapped = unsafe {
                    libc::mmap(
                        target.cast(),
                        length,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if mapped != target.cast() {
                    return Err(io::Error::last_os_error().into());
                }
            }
        }
    }
    {
        let _writing = Writing::begin();
        for (index, image) in images.iter().enumerate() {
            for segment in &image.segments {
                let source = usize::try_from(segment.file_offset)?;
                let length = usize::try_from(segment.file_size)?;
                let at = offsets[index] + usize::try_from(segment.vm_address)?;
                owned_range(at, length, size)?;
                let bytes = sources[index]
                    .get(
                        source
                            ..source
                                .checked_add(length)
                                .ok_or_else(|| failure("file copy overflow"))?,
                    )
                    .ok_or_else(|| failure("file copy exceeds image"))?;
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), arena.base.add(at), length);
                }
            }
            for &offset in &image.rebases {
                let at = offsets[index] + usize::try_from(offset)?;
                owned_range(at, 8, size)?;
                let old = unsafe { std::ptr::read_unaligned(arena.base.add(at).cast::<u64>()) };
                image
                    .segment_containing(old, 1)
                    .ok_or_else(|| failure("rebase target is not in its image"))?;
                let value = (arena.base as usize)
                    .checked_add(offsets[index])
                    .and_then(|v| v.checked_add(usize::try_from(old).ok()?))
                    .ok_or_else(|| failure("rebased address overflow"))?;
                unsafe {
                    std::ptr::write_unaligned(arena.base.add(at).cast::<u64>(), value as u64);
                }
            }
            for bind in &image.binds {
                let value = match (index, bind.library_ordinal, bind.symbol.as_str()) {
                    (1, 1, "_glue_probe_dep") => {
                        arena.base as usize + usize::try_from(images[0].exports["_glue_probe_dep"])?
                    }
                    (1, 2, "_getpid") => getpid,
                    _ => return Err(failure("unreviewed binding")),
                };
                let at = offsets[index] + usize::try_from(bind.offset)?;
                owned_range(at, 8, size)?;
                unsafe {
                    std::ptr::write_unaligned(arena.base.add(at).cast::<u64>(), value as u64);
                }
            }
        }
        for (index, image) in images.iter().enumerate() {
            for segment in &image.segments {
                let at = offsets[index] + usize::try_from(segment.vm_address)?;
                let length = usize::try_from(segment.vm_size)?;
                if segment.initial_protection & 4 != 0 {
                    unsafe {
                        sys_icache_invalidate(arena.base.add(at).cast(), length);
                    }
                } else {
                    let protection = if segment.read_only_after_fixups {
                        segment.initial_protection & !2
                    } else {
                        segment.initial_protection
                    };
                    if unsafe {
                        libc::mprotect(arena.base.add(at).cast(), length, protection as i32)
                    } != 0
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                }
            }
        }
    } // Restore JIT execute mode before any constructor or native function.
    // All offsets/exports/constructor pointer locations are already validated.
    // From this point onward, retain every mapping until process exit.
    let base = arena.base;
    std::mem::forget(arena);
    for (index, image) in images.iter().enumerate() {
        for &offset in &image.constructors {
            let location = offsets[index] + usize::try_from(offset)?;
            let address = unsafe { std::ptr::read_unaligned(base.add(location).cast::<usize>()) };
            let relative = address
                .checked_sub(base as usize + offsets[index])
                .ok_or_else(|| failure("constructor escaped image"))?;
            if !image.is_executable(relative as u64) {
                return Err(failure("constructor is not executable in its owning image"));
            }
            let constructor: unsafe extern "C" fn() = unsafe { std::mem::transmute(address) };
            // Fixtures are reviewed ordinary C: no longjmp, C++ exceptions,
            // foreign callbacks, new threads or reentrant mapping.
            unsafe {
                constructor();
            }
        }
    }
    let module_base = unsafe { base.add(offsets[1]) };
    let call = |name: &str| -> ProbeResult<i32> {
        let address = unsafe { module_base.add(usize::try_from(images[1].exports[name])?) };
        let function: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(address) };
        Ok(unsafe { function() })
    };
    let answer = call("_glue_answer")?;
    let constructors = call("_glue_probe_constructor_count")?;
    let pid = call("_glue_probe_pid")?;
    let data = unsafe {
        std::ptr::read_unaligned(
            module_base
                .add(usize::try_from(images[1].exports["_glue_probe_data"])?)
                .cast::<i32>(),
        )
    };
    if (answer, data, constructors, pid) != (42, 7, 1, unsafe { libc::getpid() })
        || call("_glue_answer")? != answer
        || call("_glue_probe_constructor_count")? != 1
    {
        return Err(failure(
            "native fixture observations differ from its exact contract",
        ));
    }
    Ok(Report {
        answer,
        data,
        constructors,
        pid,
    })
}

fn owned_range(offset: usize, length: usize, size: usize) -> ProbeResult<()> {
    if offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(failure("operation exceeds owned arena"));
    }
    Ok(())
}

fn system_getpid() -> ProbeResult<usize> {
    // The public libSystem path resolves through Apple's shared cache. Retain
    // its handle; verify the implementation belongs to the approved OS image.
    let handle = unsafe {
        libc::dlopen(
            c"/usr/lib/libSystem.B.dylib".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        )
    };
    if handle.is_null() {
        return Err(failure("cannot acquire reviewed libSystem dependency"));
    }
    let symbol = unsafe { libc::dlsym(handle, c"getpid".as_ptr()) };
    if symbol.is_null() {
        return Err(failure("libSystem lacks getpid"));
    }
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    if unsafe { libc::dladdr(symbol, info.as_mut_ptr()) } == 0 {
        return Err(failure("cannot establish getpid ownership"));
    }
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null()
        || unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes()
            != b"/usr/lib/system/libsystem_kernel.dylib"
    {
        return Err(failure("getpid resolves outside the reviewed system image"));
    }
    Ok(symbol as usize)
}
