//! Ordinary OS loading of declared compact Lua images. No Lua API is called here.
use glue_format::{DependencyProvider, DistributionSpec, PayloadKind, ResourcePath, digest};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs,
    path::{Path, PathBuf},
};

/// Only this module can create a resolved symbol token. C invokes it after the
/// Rust resource callback has returned and released all Rust borrows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Initializer {
    address: u64,
}
impl Initializer {
    pub(crate) fn address(&self) -> u64 {
        self.address
    }
}

pub(crate) struct Manager {
    roots: BTreeMap<String, PathBuf>,
    handles: BTreeMap<PathBuf, *mut libc::c_void>,
}

impl Manager {
    pub(crate) fn prepare(distribution: &DistributionSpec, root: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let mut required: BTreeSet<_> = distribution.native.roots.values().cloned().collect();
        for edge in &distribution.native.edges {
            if matches!(
                edge.provider,
                DependencyProvider::Bundled | DependencyProvider::Runtime
            ) {
                required.insert(edge.resolved.clone());
            }
        }
        // Verify every native image before any constructor can run. C05 also
        // validates the complete distribution when launching through glue.
        for deployed in required {
            ResourcePath::new(&deployed).map_err(|e| e.to_string())?;
            let record = distribution
                .payloads
                .get(&deployed)
                .ok_or_else(|| format!("native payload {deployed:?} is undeclared"))?;
            let path = root.join(&deployed);
            let canonical =
                fs::canonicalize(&path).map_err(|e| format!("native payload {deployed:?}: {e}"))?;
            if !canonical.starts_with(&root) {
                return Err(format!("native payload {deployed:?} escapes distribution"));
            }
            let bytes = match &record.kind {
                PayloadKind::Symlink { target } => {
                    let actual = fs::read_link(&path).map_err(|e| e.to_string())?;
                    if actual != Path::new(target) {
                        return Err(format!("native alias {deployed:?} changed"));
                    }
                    target.as_bytes().to_vec()
                }
                PayloadKind::File => {
                    let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
                        return Err(format!(
                            "native payload {deployed:?} is not a bounded regular file"
                        ));
                    }
                    fs::read(&path).map_err(|e| e.to_string())?
                }
            };
            if bytes.len() as u64 != record.size || digest(&bytes) != record.sha256 {
                return Err(format!(
                    "native payload {deployed:?} failed integrity verification"
                ));
            }
        }
        let family = format!("5.{}", crate::profile::LUA_MINOR);
        let mut roots = BTreeMap::new();
        for (logical, deployed) in &distribution.native.roots {
            ResourcePath::new(logical).map_err(|e| e.to_string())?;
            if !distribution
                .runtime
                .requirements
                .contains(&format!("lua-native-abi:{logical}={family}"))
            {
                return Err(format!(
                    "native Lua root {logical:?} needs an explicit matching Lua {family} ABI declaration"
                ));
            }
            roots.insert(logical.clone(), root.join(deployed));
        }
        Ok(Self {
            roots,
            handles: BTreeMap::new(),
        })
    }

    pub(crate) fn by_module(
        &mut self,
        name: &str,
    ) -> Result<Option<(String, Initializer)>, String> {
        let path = name.replace('.', "/");
        let normalized = name.replace('.', "_");
        let symbols = if let Some((prefix, suffix)) = normalized.split_once('-') {
            vec![format!("luaopen_{prefix}"), format!("luaopen_{suffix}")]
        } else {
            vec![format!("luaopen_{normalized}")]
        };
        let mut candidates = vec![
            format!("app/{path}.so"),
            format!("app/{path}.dylib"),
            format!("app/{path}/init.so"),
        ];
        if let Some((root, _)) = name.split_once('.') {
            candidates.push(format!("app/{root}.so"));
        }
        for key in candidates {
            if self.roots.contains_key(&key) {
                let mut last_error = None;
                for symbol in &symbols {
                    match self.symbol(&key, symbol) {
                        Ok(initializer) => return Ok(Some((key, initializer))),
                        Err(error) => last_error = Some(error),
                    }
                }
                return Err(last_error.expect("at least one initializer candidate"));
            }
        }
        Ok(None)
    }

    pub(crate) fn symbol(&mut self, logical: &str, symbol: &str) -> Result<Initializer, String> {
        ResourcePath::new(logical).map_err(|e| e.to_string())?;
        if symbol.is_empty()
            || !symbol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("native Lua initializer must be a C symbol name".to_owned());
        }
        let path = self
            .roots
            .get(logical)
            .ok_or_else(|| format!("native Lua resource {logical:?} is not declared"))?
            .clone();
        #[cfg(unix)]
        {
            let handle = if let Some(handle) = self.handles.get(&path) {
                *handle
            } else {
                let cpath = CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|_| "native image path contains NUL")?;
                // SAFETY: a validated, deployed native image is trusted code;
                // the terminated path remains alive through synchronous dlopen.
                let handle =
                    unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                if handle.is_null() {
                    return Err(format!("cannot load {logical:?}: {}", loader_error()));
                }
                self.handles.insert(path, handle);
                handle
            };
            let symbol = CString::new(symbol).map_err(|_| "native symbol contains NUL")?;
            // SAFETY: the handle is retained for process lifetime. dlsym merely
            // resolves bytes; Rust never invokes the resulting C/Lua function.
            unsafe {
                libc::dlerror();
            }
            let pointer = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
            if pointer.is_null() {
                return Err(format!("native initializer is missing: {}", loader_error()));
            }
            Ok(Initializer {
                address: pointer as usize as u64,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (path, symbol);
            Err("compact native Lua loading requires Linux or macOS".to_owned())
        }
    }
}

// Deliberately no dlclose: Lua/native finalizers and callbacks may retain code
// until process shutdown, including after failed initialization or Lua close.
#[cfg(unix)]
fn loader_error() -> String {
    // SAFETY: dlerror returns either NULL or a terminated loader-owned string,
    // copied before any subsequent loader operation.
    let pointer = unsafe { libc::dlerror() };
    if pointer.is_null() {
        "OS loader did not provide an error".to_owned()
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}
