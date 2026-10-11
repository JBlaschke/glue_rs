//! Private, process-pinned native closure bound to the selected stock runtime.
use super::*;
use glue_native::elf::SymbolBinding;

fn address(base: usize, offset: u64) -> Result<usize, String> {
    base.checked_add(usize::try_from(offset).map_err(|_| "native offset overflow")?)
        .ok_or_else(|| "native address overflow".into())
}
fn add_signed(base: usize, offset: i64) -> Result<usize, String> {
    if offset >= 0 {
        address(base, offset as u64)
    } else {
        base.checked_sub(
            usize::try_from(offset.unsigned_abs()).map_err(|_| "native addend overflow")?,
        )
        .ok_or_else(|| "native addend underflow".into())
    }
}
fn symbol(handle: *mut libc::c_void, name: &str) -> Result<usize, String> {
    let key = CString::new(name).map_err(|_| "native symbol contains NUL")?;
    // SAFETY: live loader handle and terminated name. No function is invoked.
    unsafe { libc::dlerror() };
    let pointer = unsafe { libc::dlsym(handle, key.as_ptr()) };
    if pointer.is_null() {
        Err(loader_error(name))
    } else {
        Ok(pointer as usize)
    }
}
fn owner(pointer: usize) -> Result<usize, String> {
    // SAFETY: dladdr only inspects the resolved address, writing valid metadata.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(pointer as *const libc::c_void, &mut info) } == 0 {
        return Err("native symbol has no loader owner".into());
    }
    Ok(info.dli_fbase as usize)
}
fn absent_global(name: &str) -> Result<(), String> {
    let key = CString::new(name).map_err(|_| "native symbol contains NUL")?;
    // SAFETY: query only, no invocation, with a terminated name.
    if !unsafe { libc::dlsym(libc::RTLD_DEFAULT, key.as_ptr()) }.is_null() {
        return Err(format!(
            "native/Python export is globally interposed: {name}"
        ));
    }
    Ok(())
}
fn sealed_file(name: &str, bytes: &[u8]) -> Result<File, String> {
    let key = CString::new(format!("glue-python-native-{name}"))
        .map_err(|_| "native memfd name contains NUL")?;
    // SAFETY: terminated name and explicit Linux executable/sealing flags.
    let fd = unsafe {
        libc::memfd_create(
            key.as_ptr(),
            libc::MFD_EXEC | libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(format!(
            "native memfd_create(MFD_EXEC): {}; no fallback",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fresh, exclusively owned descriptor returned by memfd_create.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).map_err(|e| e.to_string())?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: live descriptor, integer mask, no writable mappings.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0
        || unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } != seals
    {
        return Err("native memfd sealing failed; no fallback".into());
    }
    Ok(file)
}

pub(super) struct Registrations {
    _names: Vec<CString>,
    pub records: Vec<ExtensionRecord>,
}

pub(super) fn load(
    images: &mut [extension_profile::Image],
    runtime_handle: *mut libc::c_void,
    runtime_base: usize,
) -> Result<Registrations, String> {
    let mut runtime = BTreeMap::new();
    for name in extension_profile::PYTHON_IMPORTS {
        absent_global(name)?;
        let pointer = symbol(runtime_handle, name)?;
        if owner(pointer)? != runtime_base {
            return Err(format!(
                "selected Python native import ownership differs: {name}"
            ));
        }
        runtime.insert(name.to_string(), pointer);
    }
    for image in images.iter() {
        for entry in image
            .facts
            .symbols
            .iter()
            .filter(|s| s.defined && s.binding != SymbolBinding::Local && !s.name.is_empty())
        {
            absent_global(&entry.name)?;
        }
    }
    // Prepare the whole closure before first mapping. Host images retain their
    // verified read-only descriptor; archive images get sealed executable memfds.
    let mut files = Vec::new();
    for image in images.iter_mut() {
        files.push(match image.file.take() {
            Some(file) => file,
            None => sealed_file(&image.name, &image.bytes)?,
        });
    }
    let mut loaded: BTreeMap<String, (*mut libc::c_void, usize)> = BTreeMap::new();
    let mut bases = vec![runtime_base];
    for (image, file) in images.iter().zip(files) {
        let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        // SAFETY: admitted immutable ELF, dependency-first loading, no
        // constructors/TLS/IFUNC. The selected runtime remains RTLD_LOCAL.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(loader_error("native dlopen"));
        }
        let _pinned = ManuallyDrop::new(file);
        let mut link: *mut LinkMap = std::ptr::null_mut();
        // SAFETY: valid handle; GNU loader writes a live link_map pointer.
        if unsafe {
            libc::dlinfo(
                handle,
                libc::RTLD_DI_LINKMAP,
                (&mut link as *mut *mut LinkMap).cast(),
            )
        } != 0
            || link.is_null()
        {
            return Err(loader_error("native dlinfo"));
        }
        let base = unsafe { (*link).address };
        bases.push(base);
        // A second runtime or an undeclared dependency cannot enter the group.
        check_image_bases(bases.clone())?;
        for relocation in &image.facts.relocations {
            let expected = if relocation.kind == 1027 {
                add_signed(base, relocation.addend)?
            } else {
                let entry = &image.facts.symbols[relocation.symbol_index];
                let pointer = if entry.defined {
                    address(base, entry.value)?
                } else if let Some(pointer) = runtime.get(&entry.name) {
                    *pointer
                } else {
                    let (dependency_handle, dependency_base) = loaded
                        .get(extension_profile::DEPENDENCY)
                        .ok_or("native dependency is not loaded first")?;
                    let pointer = symbol(*dependency_handle, &entry.name)?;
                    if owner(pointer)? != *dependency_base {
                        return Err("private dependency symbol ownership differs".into());
                    }
                    pointer
                };
                add_signed(pointer, relocation.addend)?
            };
            let slot = address(base, relocation.offset)?;
            if !slot.is_multiple_of(std::mem::align_of::<usize>()) {
                return Err("native relocation slot is misaligned".into());
            }
            // SAFETY: portable ELF inspection proves a pointer-width readable
            // relocation target within a live, permanently pinned PT_LOAD.
            if unsafe { (slot as *const usize).read() } != expected {
                return Err(format!(
                    "native relocation ownership differs: {}",
                    image.name
                ));
            }
        }
        loaded.insert(image.name.clone(), (handle, base));
    }
    // Verify local visibility again after every root has been mapped. A matching
    // SONAME alone is insufficient; all actual function AND data slots matched.
    for name in extension_profile::PYTHON_IMPORTS {
        absent_global(name)?;
    }
    let names: Vec<_> = extension_profile::ROOTS
        .iter()
        .map(|name| CString::new(*name).unwrap())
        .collect();
    let mut records = Vec::new();
    for name in &names {
        let image_name = format!("{}.so", name.to_str().unwrap());
        let (handle, base) = loaded[&image_name];
        let export = format!("PyInit_{}", name.to_str().unwrap());
        let image = images.iter().find(|i| i.name == image_name).unwrap();
        let entry = image
            .facts
            .symbol(&export)
            .ok_or("missing admitted native initializer")?;
        let pointer = symbol(handle, &export)?;
        if pointer != address(base, entry.value)? || owner(pointer)? != base {
            return Err("native initializer ownership differs".into());
        }
        absent_global(&export)?;
        records.push(ExtensionRecord {
            name: name.as_ptr(),
            initializer: pointer as *const libc::c_void,
        });
    }
    Ok(Registrations {
        _names: names,
        records,
    })
}
