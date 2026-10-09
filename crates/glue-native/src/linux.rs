//! The only unsafe boundary of the experimental native closure loader.
//! All payload offsets/symbols were checked by portable inspection. OS loader
//! metadata is trusted; payload code obeys the controlled C ABI contract.

use super::*;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    mem::ManuallyDrop,
    os::fd::{AsRawFd, FromRawFd},
    sync::atomic::{AtomicBool, Ordering},
};

static ATTEMPTED: AtomicBool = AtomicBool::new(false);
const SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub(super) fn load(plan: NativePlan) -> Result<NativeManager, NativeError> {
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
        if std::env::var_os(name).is_some_and(|value| !value.is_empty()) {
            return Err(unsupported(format!(
                "loader override {name} is not supported"
            )));
        }
    }
    // SAFETY: scalar OS query with a defined selector, before any Lua state.
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
        return Err(unsupported("requires a 4096-byte host page size"));
    }
    if ATTEMPTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(unsupported(
            "only one native closure attempt is supported per process",
        ));
    }
    let main_base = check_loaded_images(&plan)?;
    let mut runtime = BTreeMap::new();
    for name in &plan.runtime_exports {
        let address = symbol(libc::RTLD_DEFAULT, name, None)?;
        if owner(address)?.0 != main_base {
            return Err(invalid(format!(
                "Lua export {name} is not owned by the launcher"
            )));
        }
        runtime.insert(name.clone(), address);
    }
    let mut os = BTreeMap::new();
    // Check interposition before dlopen can run a constructor. Each defined
    // payload name is unique across the verified closure and absent globally.
    for image in plan.images.values() {
        for entry in &image.facts.symbols {
            if exported(entry) && optional_symbol(&entry.name)?.is_some() {
                return Err(invalid(format!(
                    "pre-existing global export {}",
                    entry.name
                )));
            }
        }
        for (index, provider) in &image.providers {
            match provider {
                Provider::OperatingSystem {
                    symbol: name,
                    version,
                } => {
                    let address = symbol(libc::RTLD_DEFAULT, name, Some(version))?;
                    let (_, path) = owner(address)?;
                    if path.rsplit('/').next() != Some("libc.so.6")
                        || optional_symbol(name)? != Some(address)
                    {
                        return Err(invalid(format!("OS import {name}@{version} is interposed")));
                    }
                    os.insert((name.clone(), version.clone()), address);
                }
                Provider::WeakNull => {
                    let name = &image.facts.symbols[*index].name;
                    if optional_symbol(name)?.is_some() {
                        return Err(unsupported("weak imports must remain unresolved"));
                    }
                }
                _ => {}
            }
        }
    }
    let mut sealed = BTreeMap::new();
    // All descriptors are sealed before the first dlopen / constructor.
    for id in &plan.order {
        let image = &plan.images[id];
        sealed.insert(
            id.clone(),
            SealedImage::new(&image.facts.soname, &image.bytes)?,
        );
    }
    let mut loaded: BTreeMap<String, LoadedImage> = BTreeMap::new();
    for id in &plan.order {
        let image = &plan.images[id];
        let handle = sealed.remove(id).expect("prepared descriptor").load()?;
        // Eager relocation has already completed. Inspect every admitted slot,
        // including self definitions and relative relocations, before publishing
        // any initializer. RELRO changes write permission, not read permission.
        for relocation in &image.facts.relocations {
            let expected = if relocation.kind == 1027 {
                add_signed(handle.base, relocation.addend)?
            } else {
                let entry = &image.facts.symbols[relocation.symbol_index];
                let address = if entry.defined {
                    address(handle.base, entry.value)?
                } else {
                    match &image.providers[&entry.index] {
                        Provider::Runtime(name) => runtime[name],
                        Provider::OperatingSystem { symbol, version } => {
                            os[&(symbol.clone(), version.clone())]
                        }
                        Provider::Archived { module, symbol } => address(
                            loaded[module].base,
                            plan.images[module].facts.symbols[*symbol].value,
                        )?,
                        Provider::WeakNull => 0,
                    }
                };
                add_signed(address, relocation.addend)?
            };
            let slot = address(handle.base, relocation.offset)?;
            if !slot.is_multiple_of(std::mem::align_of::<usize>()) {
                return Err(invalid("misaligned relocation slot"));
            }
            // SAFETY: inspection proves this pointer-width slot lies in a
            // mapped, readable PT_LOAD range. The loaded image stays pinned.
            let actual = unsafe { (slot as *const usize).read() };
            if actual != expected {
                return Err(invalid(format!(
                    "{id}: resolved import/relocation ownership differs"
                )));
            }
        }
        loaded.insert(id.clone(), handle);
    }
    let mut roots = BTreeMap::new();
    for (name, root) in plan.roots {
        let image = &loaded[&root.module];
        let entry = plan.images[&root.module]
            .facts
            .symbol(&root.symbol)
            .expect("validated initializer");
        let actual = symbol(image.handle, &root.symbol, None)?;
        if actual != address(image.base, entry.value)? || owner(actual)?.0 != image.base {
            return Err(invalid(
                "initializer is not owned by its declared native image",
            ));
        }
        roots.insert(
            name,
            (
                root,
                NativeInitializer {
                    address: actual as u64,
                },
            ),
        );
    }
    Ok(NativeManager { roots })
}

struct SealedImage(File);

impl SealedImage {
    fn new(soname: &str, bytes: &[u8]) -> Result<Self, NativeError> {
        let name = CString::new(format!("glue-lua-native-{soname}"))
            .map_err(|_| invalid("memfd name contains NUL"))?;
        // SAFETY: live terminated name and explicit Linux flags. There is no
        // implicit-execute or filesystem fallback on unsupported policy/kernel.
        let descriptor = unsafe {
            libc::memfd_create(
                name.as_ptr(),
                libc::MFD_EXEC | libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if descriptor < 0 {
            return Err(unsupported(format!(
                "memfd_create(MFD_EXEC): {}; no fallback",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful memfd_create returns a fresh exclusively owned fd.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        file.write_all(bytes)
            .map_err(|error| failure(error.to_string()))?;
        // SAFETY: live descriptor; integer seal mask; no writable mapping exists.
        if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, SEALS) } < 0 {
            return Err(failure(format!(
                "sealing memfd: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: query of a live memfd, with no third argument.
        if unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) } != SEALS {
            return Err(failure("memfd seals differ from the required four seals"));
        }
        Ok(Self(file))
    }

    fn load(self) -> Result<LoadedImage, NativeError> {
        let path =
            CString::new(format!("/proc/self/fd/{}", self.0.as_raw_fd())).expect("numeric fd path");
        // SAFETY: verified and sealed ELF bytes, dependency-first local scope;
        // all constructors run before any Lua state exists. Native C code must
        // not throw foreign exceptions or call back into a Lua state here.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(failure(loader_error("dlopen")));
        }
        // Pin immediately, including any later validation/error return.
        let file = ManuallyDrop::new(self.0);
        let mut link: *mut LinkMap = std::ptr::null_mut();
        // SAFETY: valid dlopen handle, GNU RTLD_DI_LINKMAP writes a link_map*.
        if unsafe {
            libc::dlinfo(
                handle,
                libc::RTLD_DI_LINKMAP,
                (&mut link as *mut *mut LinkMap).cast(),
            )
        } != 0
            || link.is_null()
        {
            return Err(failure(loader_error("dlinfo")));
        }
        // SAFETY: loader-owned metadata of the live process-pinned handle.
        let base = unsafe { (*link).address };
        Ok(LoadedImage {
            _file: file,
            handle,
            base,
        })
    }
}

// The prefix of GNU link_map from <link.h>; we only read l_addr.
#[repr(C)]
struct LinkMap {
    address: usize,
}

// No dlclose or descriptor-closing Drop path: even initializer failure and Lua
// finalizers may retain native C closures. General reclamation is later work.
struct LoadedImage {
    _file: ManuallyDrop<File>,
    handle: *mut libc::c_void,
    base: usize,
}

fn symbol(
    handle: *mut libc::c_void,
    name: &str,
    version: Option<&str>,
) -> Result<usize, NativeError> {
    let name = CString::new(name).map_err(|_| invalid("symbol contains NUL"))?;
    // SAFETY: clear thread-local loader error before the lookup.
    unsafe {
        libc::dlerror();
    }
    let pointer = if let Some(version) = version {
        let version = CString::new(version).map_err(|_| invalid("version contains NUL"))?;
        // SAFETY: terminated strings and OS-owned handle/default scope.
        unsafe { libc::dlvsym(handle, name.as_ptr(), version.as_ptr()) }
    } else {
        // SAFETY: terminated string and OS-owned handle/default scope.
        unsafe { libc::dlsym(handle, name.as_ptr()) }
    };
    // SAFETY: thread-local loader error, copied before another loader call.
    let error = unsafe { libc::dlerror() };
    if !error.is_null() || pointer.is_null() {
        return Err(failure(format!(
            "missing reviewed symbol {}",
            name.to_string_lossy()
        )));
    }
    Ok(pointer as usize)
}

fn optional_symbol(name: &str) -> Result<Option<usize>, NativeError> {
    let name = CString::new(name).map_err(|_| invalid("symbol contains NUL"))?;
    // SAFETY: defined OS loader calls with a terminated string. Missing symbols
    // in already loaded scope do not search the filesystem or load an image.
    unsafe {
        libc::dlerror();
        let pointer = libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr());
        let error = libc::dlerror();
        if error.is_null() && !pointer.is_null() {
            Ok(Some(pointer as usize))
        } else {
            Ok(None)
        }
    }
}

fn owner(address: usize) -> Result<(usize, String), NativeError> {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::uninit();
    // SAFETY: scalar symbol address and writable Dl_info output.
    if unsafe { libc::dladdr(address as *const libc::c_void, info.as_mut_ptr()) } == 0 {
        return Err(invalid("symbol has no loaded-image owner"));
    }
    // SAFETY: successful dladdr initialized its output structure.
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null() {
        return Err(invalid("symbol owner has no name"));
    }
    // SAFETY: dladdr's process-pinned, terminated image name.
    let name = unsafe { CStr::from_ptr(info.dli_fname) }
        .to_string_lossy()
        .into_owned();
    Ok((info.dli_fbase as usize, name))
}

fn check_loaded_images(plan: &NativePlan) -> Result<usize, NativeError> {
    let mut images: Vec<(String, usize)> = Vec::new();
    unsafe extern "C" fn collect(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        // SAFETY: dl_iterate_phdr supplies live initialized OS metadata and the
        // exact exclusive Vec pointer passed below. No Lua state exists.
        unsafe {
            let images = &mut *data.cast::<Vec<(String, usize)>>();
            if images.len() >= 32 || info.is_null() || (*info).dlpi_name.is_null() {
                return 1;
            }
            let name = CStr::from_ptr((*info).dlpi_name)
                .to_string_lossy()
                .into_owned();
            images.push((name, (*info).dlpi_addr as usize));
        }
        0
    }
    // SAFETY: synchronous OS enumeration; callback/context remain live until
    // return and do not invoke arbitrary code or a Lua API.
    if unsafe {
        libc::dl_iterate_phdr(
            Some(collect),
            (&mut images as *mut Vec<(String, usize)>).cast(),
        )
    } != 0
    {
        return Err(unsupported(
            "loaded-image inventory exceeds the bounded profile",
        ));
    }
    let mut main = None;
    for (name, base) in images {
        if name.is_empty() {
            main = Some(base);
            continue;
        }
        let basename = name.rsplit('/').next().unwrap_or("");
        if plan
            .images
            .values()
            .any(|image| image.facts.soname == basename)
        {
            return Err(invalid("native SONAME already loaded"));
        }
        let known = name == "linux-vdso.so.1"
            || name == "/lib/ld-linux-aarch64.so.1"
            || ["/lib/aarch64-linux-gnu/", "/usr/lib/aarch64-linux-gnu/"]
                .iter()
                .any(|prefix| {
                    name.strip_prefix(prefix).is_some_and(|tail| {
                        matches!(
                            tail,
                            "libc.so.6" | "libm.so.6" | "libgcc_s.so.1" | "ld-linux-aarch64.so.1"
                        )
                    })
                });
        if !known {
            return Err(unsupported(format!(
                "pre-existing image {basename:?} is outside the observed OS closure"
            )));
        }
    }
    main.ok_or_else(|| invalid("launcher image was not identified"))
}

fn address(base: usize, offset: u64) -> Result<usize, NativeError> {
    base.checked_add(usize::try_from(offset).map_err(|_| invalid("address offset overflow"))?)
        .ok_or_else(|| invalid("loaded address overflow"))
}

fn add_signed(base: usize, addend: i64) -> Result<usize, NativeError> {
    base.checked_add_signed(isize::try_from(addend).map_err(|_| invalid("addend overflow"))?)
        .ok_or_else(|| invalid("loaded relocation overflow"))
}

fn loader_error(context: &str) -> String {
    // SAFETY: loader error is thread-local; copy before the next loader call.
    let pointer = unsafe { libc::dlerror() };
    if pointer.is_null() {
        return format!("{context} failed without a diagnostic");
    }
    // SAFETY: nonnull loader error points at terminated OS-owned text.
    format!(
        "{context}: {}",
        unsafe { CStr::from_ptr(pointer) }.to_string_lossy()
    )
}

fn failure(message: impl Into<String>) -> NativeError {
    NativeError::Load(message.into())
}
