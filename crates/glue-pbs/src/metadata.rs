//! Validate a narrow PBS metadata profile against an already bounded inventory.
//!
//! Metadata describes the upstream build. It does not establish the runtime's
//! actual imports, extension registration, or ability to initialize in memory.

use crate::archive::{EntryKind, Inventory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataReport {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub metadata_version: String,
    pub python_version: String,
    pub target_triple: String,
    pub build_options: String,
    pub gil: String,
    pub debug: bool,
    pub libpython_link_mode: String,
    pub runtime_library: FileIdentity,
    pub stdlib: String,
    /// Presence and identity checks only; interpreter startup is unobserved.
    pub encodings_resources: Vec<FileIdentity>,
    pub math: ExtensionCandidate,
    pub ssl: ExtensionCandidate,
    /// Upstream linker metadata, not an observed runtime dependency closure.
    pub core_links: Vec<LinkRequirement>,
    /// Preserve upstream claims verbatim, including malformed version claims.
    pub crt_features: Vec<String>,
    pub inittab_source: FileIdentity,
    pub inittab_object: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileIdentity {
    pub path: String,
    pub resolved_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionCandidate {
    pub name: String,
    pub variant: String,
    pub init_fn: String,
    pub in_core: bool,
    pub required: bool,
    pub linkage: ExtensionLinkage,
    pub shared_library: Option<FileIdentity>,
    pub static_library: Option<FileIdentity>,
    pub objects: Vec<FileIdentity>,
    pub links: Vec<LinkRequirement>,
    pub registration_observed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionLinkage {
    SharedLibraryDeclared,
    CoreDeclared,
    StaticObjectsDeclared,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LinkRequirement {
    pub name: String,
    pub system: bool,
    pub framework: bool,
    pub static_library: Option<FileIdentity>,
    pub dynamic_library: Option<FileIdentity>,
}

#[derive(Deserialize)]
struct Metadata {
    version: String,
    target_triple: String,
    python_version: String,
    python_major_minor_version: String,
    python_implementation_name: String,
    python_tag: String,
    python_abi_tag: Option<String>,
    python_implementation_cache_tag: String,
    build_options: String,
    libpython_link_mode: String,
    python_symbol_visibility: String,
    python_extension_module_loading: Vec<String>,
    python_paths: std::collections::BTreeMap<String, String>,
    python_config_vars: std::collections::BTreeMap<String, String>,
    crt_features: Vec<String>,
    build_info: BuildInfo,
}

#[derive(Deserialize)]
struct BuildInfo {
    core: Core,
    extensions: std::collections::BTreeMap<String, Vec<Extension>>,
    inittab_source: String,
    inittab_object: String,
}

#[derive(Deserialize)]
struct Core {
    shared_lib: Option<String>,
    links: Vec<Link>,
}

#[derive(Deserialize)]
struct Extension {
    variant: String,
    init_fn: String,
    in_core: bool,
    required: bool,
    shared_lib: Option<String>,
    static_lib: Option<String>,
    #[serde(default)]
    objs: Vec<String>,
    links: Vec<Link>,
}

#[derive(Deserialize)]
struct Link {
    name: String,
    #[serde(default)]
    system: bool,
    #[serde(default)]
    framework: bool,
    path_static: Option<String>,
    path_dynamic: Option<String>,
}

pub fn inspect_metadata(
    inventory: &Inventory,
    expected_version: &str,
    expected_target: &str,
    expected_build_options: &str,
) -> Result<MetadataReport> {
    if !expected_version.starts_with("3.13.")
        || expected_version.split('.').count() != 3
        || !expected_version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        || expected_target != "aarch64-unknown-linux-gnu"
        || expected_build_options != "pgo+lto"
    {
        return Err("unsupported PBS metadata profile; requires CPython 3.13, aarch64-unknown-linux-gnu, pgo+lto".into());
    }
    let bytes = inventory
        .metadata
        .as_ref()
        .ok_or("full PBS archive is missing python/PYTHON.json")?;
    let value = crate::strict_json(bytes)?;
    let metadata: Metadata =
        serde_json::from_value(value).map_err(|error| format!("invalid PBS metadata: {error}"))?;
    let metadata_identity = file(inventory, "python/PYTHON.json")?;
    let digest = crate::hex_digest(&Sha256::digest(bytes));
    if metadata_identity.path != metadata_identity.resolved_path
        || metadata_identity.size != bytes.len() as u64
        || metadata_identity.sha256 != digest
    {
        return Err("PBS metadata bytes disagree with regular-file inventory identity".into());
    }
    require(&metadata.version, "8", "metadata version")?;
    require(&metadata.python_version, expected_version, "Python version")?;
    require(&metadata.target_triple, expected_target, "target triple")?;
    require(
        &metadata.build_options,
        expected_build_options,
        "build options",
    )?;
    require(
        &metadata.python_major_minor_version,
        "3.13",
        "Python major/minor",
    )?;
    require(
        &metadata.python_implementation_name,
        "cpython",
        "implementation",
    )?;
    require(&metadata.python_tag, "cp313", "Python tag")?;
    if metadata
        .python_abi_tag
        .as_deref()
        .is_some_and(|tag| !matches!(tag, "" | "cp313"))
    {
        return Err("unsupported Python ABI tag".into());
    }
    require(
        &metadata.python_implementation_cache_tag,
        "cpython-313",
        "implementation cache tag",
    )?;
    require(
        &metadata.libpython_link_mode,
        "shared",
        "libpython link mode",
    )?;
    require(
        &metadata.python_symbol_visibility,
        "global-default",
        "Python symbol visibility",
    )?;
    if metadata.python_extension_module_loading != ["builtin", "shared-library"] {
        return Err("unsupported Python extension loading declaration".into());
    }
    for (key, expected) in [
        ("Py_GIL_DISABLED", "0"),
        ("Py_DEBUG", "0"),
        ("Py_ENABLE_SHARED", "1"),
        ("SIZEOF_VOID_P", "8"),
        ("ABIFLAGS", ""),
        ("VERSION", "3.13"),
        ("LDVERSION", "3.13"),
        ("SOABI", "cpython-313-aarch64-linux-gnu"),
        ("MULTIARCH", "aarch64-linux-gnu"),
    ] {
        let actual = metadata
            .python_config_vars
            .get(key)
            .ok_or_else(|| format!("PBS metadata is missing config variable {key}"))?;
        require(actual, expected, key)?;
    }

    let runtime_path = metadata
        .build_info
        .core
        .shared_lib
        .as_deref()
        .ok_or("PBS metadata does not declare a shared libpython")?;
    let runtime_path = installation_path(runtime_path)?;
    let runtime_library = installation_file(inventory, &runtime_path)?;
    elf_library(inventory, &runtime_library)?;
    let stdlib = installation_path(
        metadata
            .python_paths
            .get("stdlib")
            .ok_or("PBS metadata does not declare python_paths.stdlib")?,
    )?;
    // PBS's real archives omit directory headers. The required children below
    // establish an implicit directory; an explicit non-directory is forbidden.
    if inventory
        .entries
        .get(&stdlib)
        .is_some_and(|entry| entry.kind != EntryKind::Directory)
    {
        return Err("PBS stdlib must identify an archive directory".into());
    }
    let encodings_resources = [
        "codecs.py",
        "encodings/__init__.py",
        "encodings/aliases.py",
        "encodings/ascii.py",
        "encodings/latin_1.py",
        "encodings/utf_8.py",
    ]
    .into_iter()
    .map(|suffix| installation_file(inventory, &format!("{stdlib}/{suffix}")))
    .collect::<Result<Vec<_>>>()?;
    let math = extension(inventory, &metadata.build_info, "math", "PyInit_math")?;
    let ssl = extension(inventory, &metadata.build_info, "_ssl", "PyInit__ssl")?;
    let core_links = links(inventory, &metadata.build_info.core.links)?;
    let inittab_source = metadata_file(inventory, &metadata.build_info.inittab_source)?;
    let inittab_object = metadata_file(inventory, &metadata.build_info.inittab_object)?;

    Ok(MetadataReport {
        path: metadata_identity.path,
        size: metadata_identity.size,
        sha256: digest,
        metadata_version: metadata.version,
        python_version: metadata.python_version,
        target_triple: metadata.target_triple,
        build_options: metadata.build_options,
        gil: "conventional".into(),
        debug: false,
        libpython_link_mode: metadata.libpython_link_mode,
        runtime_library,
        stdlib,
        encodings_resources,
        math,
        ssl,
        core_links,
        crt_features: metadata.crt_features,
        inittab_source,
        inittab_object,
    })
}

fn require(actual: &str, expected: &str, field: &str) -> Result<()> {
    if actual != expected {
        return Err(format!(
            "PBS {field} {actual:?} does not match {expected:?}"
        ));
    }
    Ok(())
}

fn metadata_path(relative: &str) -> Result<String> {
    if relative.is_empty()
        || relative.len() > 4096
        || !relative.is_ascii()
        || relative
            .bytes()
            .any(|byte| byte.is_ascii_control() || b"\\<>:\"|?*".contains(&byte))
        || relative.split('/').count() > 64
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(format!("noncanonical PBS metadata path {relative:?}"));
    }
    Ok(format!("python/{relative}"))
}

fn installation_path(relative: &str) -> Result<String> {
    let path = metadata_path(relative)?;
    if !path.starts_with("python/install/") {
        return Err("runtime library and stdlib must be inside the PBS installation".into());
    }
    Ok(path)
}

fn metadata_file(inventory: &Inventory, relative: &str) -> Result<FileIdentity> {
    file(inventory, &metadata_path(relative)?)
}

fn installation_file(inventory: &Inventory, path: &str) -> Result<FileIdentity> {
    let identity = file(inventory, path)?;
    if !identity.resolved_path.starts_with("python/install/") {
        return Err(format!(
            "PBS installation resource resolves outside installation: {path}"
        ));
    }
    Ok(identity)
}

fn file(inventory: &Inventory, path: &str) -> Result<FileIdentity> {
    let entry = inventory
        .entries
        .get(path)
        .ok_or_else(|| format!("PBS metadata resource is missing: {path}"))?;
    let resolved_path = match entry.kind {
        EntryKind::RegularFile => path,
        EntryKind::Symlink | EntryKind::Hardlink => entry
            .resolved_target
            .as_deref()
            .ok_or_else(|| format!("PBS metadata resource link is unresolved: {path}"))?,
        EntryKind::Directory => {
            return Err(format!("PBS metadata resource is a directory: {path}"));
        }
    };
    let resolved = inventory
        .entries
        .get(resolved_path)
        .filter(|entry| entry.kind == EntryKind::RegularFile)
        .ok_or_else(|| format!("PBS metadata resource does not resolve to a file: {path}"))?;
    let sha256 = resolved
        .sha256
        .clone()
        .ok_or_else(|| format!("PBS metadata resource has no file digest: {path}"))?;
    if resolved.size == 0 {
        return Err(format!("PBS metadata resource is empty: {path}"));
    }
    Ok(FileIdentity {
        path: path.to_owned(),
        resolved_path: resolved_path.to_owned(),
        size: resolved.size,
        sha256,
    })
}

fn elf_library(inventory: &Inventory, identity: &FileIdentity) -> Result<()> {
    let prefix = inventory
        .binary_prefixes
        .get(&identity.resolved_path)
        .ok_or("PBS shared library is missing a recognized binary header")?;
    if identity.size < 64
        || prefix.len() < 64
        || &prefix[..7] != b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes([prefix[16], prefix[17]]) != 3
        || u16::from_le_bytes([prefix[18], prefix[19]]) != 183
        || u32::from_le_bytes(prefix[20..24].try_into().unwrap()) != 1
        || u16::from_le_bytes([prefix[52], prefix[53]]) != 64
    {
        return Err(
            "PBS shared library must have an ELF64 little-endian AArch64 ET_DYN header".into(),
        );
    }
    Ok(())
}

fn extension(
    inventory: &Inventory,
    build: &BuildInfo,
    name: &str,
    init_fn: &str,
) -> Result<ExtensionCandidate> {
    let candidates = build
        .extensions
        .get(name)
        .ok_or_else(|| format!("PBS metadata does not declare extension {name}"))?;
    if candidates.len() != 1 {
        return Err(format!(
            "PBS extension {name} requires exactly one candidate"
        ));
    }
    let candidate = &candidates[0];
    require(&candidate.variant, "default", "extension variant")?;
    require(&candidate.init_fn, init_fn, "extension initializer")?;
    let shared_library = candidate
        .shared_lib
        .as_deref()
        .map(|path| installation_path(path).and_then(|path| installation_file(inventory, &path)))
        .transpose()?;
    if let Some(shared) = &shared_library {
        elf_library(inventory, shared)?;
    }
    let static_library = candidate
        .static_lib
        .as_deref()
        .map(|path| metadata_file(inventory, path))
        .transpose()?;
    let objects = candidate
        .objs
        .iter()
        .map(|path| metadata_file(inventory, path))
        .collect::<Result<Vec<_>>>()?;
    if candidate.in_core && shared_library.is_some() {
        return Err(format!(
            "PBS extension {name} contradicts its in_core declaration"
        ));
    }
    let linkage = if shared_library.is_some() {
        ExtensionLinkage::SharedLibraryDeclared
    } else if candidate.in_core {
        ExtensionLinkage::CoreDeclared
    } else if static_library.is_some() || !objects.is_empty() {
        ExtensionLinkage::StaticObjectsDeclared
    } else {
        return Err(format!(
            "PBS extension {name} has no declared implementation resource"
        ));
    };
    Ok(ExtensionCandidate {
        name: name.into(),
        variant: candidate.variant.clone(),
        init_fn: candidate.init_fn.clone(),
        in_core: candidate.in_core,
        required: candidate.required,
        linkage,
        shared_library,
        static_library,
        objects,
        links: links(inventory, &candidate.links)?,
        registration_observed: false,
    })
}

fn links(inventory: &Inventory, declarations: &[Link]) -> Result<Vec<LinkRequirement>> {
    declarations
        .iter()
        .map(|link| {
            if link.name.is_empty()
                || link.name.len() > 255
                || !link.name.is_ascii()
                || !link
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
                || link.framework
                || (link.system && (link.path_static.is_some() || link.path_dynamic.is_some()))
            {
                return Err("unsupported or contradictory PBS link declaration".into());
            }
            let static_library = link
                .path_static
                .as_deref()
                .map(|path| metadata_file(inventory, path))
                .transpose()?;
            let dynamic_library = link
                .path_dynamic
                .as_deref()
                .map(|path| metadata_file(inventory, path))
                .transpose()?;
            if !link.system && static_library.is_none() && dynamic_library.is_none() {
                return Err("non-system PBS link requires an inventoried library".into());
            }
            Ok(LinkRequirement {
                name: link.name.clone(),
                system: link.system,
                framework: link.framework,
                static_library,
                dynamic_library,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Entry;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    fn fixture() -> (Inventory, Value) {
        let mut entries = BTreeMap::new();
        let mut binary_prefixes = BTreeMap::new();
        let runtime = "python/install/lib/libpython3.13.so.1.0";
        for path in [
            runtime,
            "python/install/lib/python3.13/codecs.py",
            "python/install/lib/python3.13/encodings/__init__.py",
            "python/install/lib/python3.13/encodings/aliases.py",
            "python/install/lib/python3.13/encodings/ascii.py",
            "python/install/lib/python3.13/encodings/latin_1.py",
            "python/install/lib/python3.13/encodings/utf_8.py",
            "python/build/Modules/mathmodule.o",
            "python/build/Modules/_ssl.o",
            "python/build/Modules/config.c",
            "python/build/Modules/config.o",
            "python/build/lib/libcrypto.a",
            "python/build/lib/libssl.a",
        ] {
            entries.insert(path.into(), regular(b"fixture"));
        }
        let mut elf = vec![0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        entries.insert(runtime.into(), regular(&elf));
        binary_prefixes.insert(runtime.into(), elf);
        let inventory = Inventory {
            entries,
            metadata: None,
            decompressed_bytes: 0,
            binary_prefixes,
        };
        let metadata = json!({
            "version":"8", "python_version":"3.13.16",
            "target_triple":"aarch64-unknown-linux-gnu", "build_options":"pgo+lto",
            "python_major_minor_version":"3.13", "python_implementation_name":"cpython",
            "python_tag":"cp313", "python_abi_tag":"",
            "python_implementation_cache_tag":"cpython-313",
            "libpython_link_mode":"shared", "python_symbol_visibility":"global-default",
            "python_extension_module_loading":["builtin","shared-library"],
            "python_paths":{"stdlib":"install/lib/python3.13"},
            "python_config_vars":{
                "Py_GIL_DISABLED":"0", "Py_DEBUG":"0", "Py_ENABLE_SHARED":"1",
                "SIZEOF_VOID_P":"8", "ABIFLAGS":"", "VERSION":"3.13", "LDVERSION":"3.13",
                "SOABI":"cpython-313-aarch64-linux-gnu", "MULTIARCH":"aarch64-linux-gnu"
            },
            "crt_features":["glibc-dynamic","glibc-max-symbol-version:2.17)"],
            "build_info":{
                "core":{"shared_lib":"install/lib/libpython3.13.so.1.0","links":[{"name":"pthread","system":true}]},
                "inittab_source":"build/Modules/config.c", "inittab_object":"build/Modules/config.o",
                "extensions":{
                    "math":[{"variant":"default","init_fn":"PyInit_math","in_core":false,"required":false,"objs":["build/Modules/mathmodule.o"],"links":[{"name":"m","system":true}]}],
                    "_ssl":[{"variant":"default","init_fn":"PyInit__ssl","in_core":false,"required":false,"objs":["build/Modules/_ssl.o"],"links":[{"name":"crypto","path_static":"build/lib/libcrypto.a"},{"name":"ssl","path_static":"build/lib/libssl.a"}]}]
                }
            }
        });
        (inventory, metadata)
    }

    fn regular(bytes: &[u8]) -> Entry {
        Entry {
            kind: EntryKind::RegularFile,
            size: bytes.len() as u64,
            mode: 0o644,
            sha256: Some(crate::hex_digest(&Sha256::digest(bytes))),
            link_target: None,
            resolved_target: None,
        }
    }

    fn directory() -> Entry {
        Entry {
            kind: EntryKind::Directory,
            size: 0,
            mode: 0o755,
            sha256: None,
            link_target: None,
            resolved_target: None,
        }
    }

    fn set_metadata(inventory: &mut Inventory, metadata: &Value) {
        let bytes = serde_json::to_vec(metadata).unwrap();
        inventory
            .entries
            .insert("python/PYTHON.json".into(), regular(&bytes));
        inventory.metadata = Some(bytes);
    }

    fn inspect(inventory: &Inventory) -> Result<MetadataReport> {
        inspect_metadata(inventory, "3.13.16", "aarch64-unknown-linux-gnu", "pgo+lto")
    }

    #[test]
    fn records_static_candidates_without_claiming_builtin_registration() {
        let (mut inventory, metadata) = fixture();
        set_metadata(&mut inventory, &metadata);
        let report = inspect(&inventory).unwrap();
        assert_eq!(report.math.linkage, ExtensionLinkage::StaticObjectsDeclared);
        assert_eq!(report.ssl.linkage, ExtensionLinkage::StaticObjectsDeclared);
        assert!(!report.math.registration_observed);
        assert!(!report.ssl.registration_observed);
        assert_eq!(report.encodings_resources.len(), 6);
        assert_eq!(report.crt_features[1], "glibc-max-symbol-version:2.17)");
        assert_eq!(
            report.ssl.links[0]
                .static_library
                .as_ref()
                .unwrap()
                .resolved_path,
            "python/build/lib/libcrypto.a"
        );
    }

    #[test]
    fn rejects_contradictory_identity_and_abi_claims() {
        for (field, value) in [
            ("version", json!("7")),
            ("python_version", json!("3.13.15")),
            ("target_triple", json!("x86_64-unknown-linux-gnu")),
            ("build_options", json!("pgo+lto+freethreaded")),
            ("python_major_minor_version", json!("3.14")),
            ("python_implementation_name", json!("pypy")),
            ("python_tag", json!("cp314")),
            ("python_abi_tag", json!("cp313t")),
            ("python_implementation_cache_tag", json!("cpython-314")),
            ("libpython_link_mode", json!("static")),
            ("python_symbol_visibility", json!("hidden")),
            ("python_extension_module_loading", json!(["builtin"])),
        ] {
            let (mut inventory, mut metadata) = fixture();
            metadata[field] = value;
            set_metadata(&mut inventory, &metadata);
            assert!(inspect(&inventory).is_err(), "accepted {field}");
        }
        for field in [
            "Py_GIL_DISABLED",
            "Py_DEBUG",
            "Py_ENABLE_SHARED",
            "SIZEOF_VOID_P",
            "ABIFLAGS",
            "VERSION",
            "LDVERSION",
            "SOABI",
            "MULTIARCH",
        ] {
            let (mut inventory, mut metadata) = fixture();
            metadata["python_config_vars"][field] = json!("contradiction");
            set_metadata(&mut inventory, &metadata);
            assert!(inspect(&inventory).is_err(), "accepted {field}");
        }
    }

    #[test]
    fn rejects_duplicate_json_keys_including_unused_fields() {
        let (mut inventory, metadata) = fixture();
        let serialized = serde_json::to_string(&metadata).unwrap();
        let bytes = format!(
            "{{\"unused\":{{\"nested\":1,\"nested\":2}},{}}}",
            &serialized[1..serialized.len() - 1]
        )
        .into_bytes();
        inventory
            .entries
            .insert("python/PYTHON.json".into(), regular(&bytes));
        inventory.metadata = Some(bytes);
        assert!(inspect(&inventory).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn requires_metadata_bytes_to_match_inventory() {
        let (mut inventory, metadata) = fixture();
        set_metadata(&mut inventory, &metadata);
        inventory
            .entries
            .get_mut("python/PYTHON.json")
            .unwrap()
            .sha256 = Some("00".repeat(32));
        assert!(inspect(&inventory).unwrap_err().contains("identity"));
    }

    #[test]
    fn rejects_missing_startup_or_static_candidate_resources() {
        for path in [
            "python/install/lib/libpython3.13.so.1.0",
            "python/install/lib/python3.13/encodings/__init__.py",
            "python/install/lib/python3.13/encodings/aliases.py",
            "python/install/lib/python3.13/codecs.py",
            "python/build/Modules/mathmodule.o",
            "python/build/lib/libssl.a",
            "python/build/Modules/config.c",
        ] {
            let (mut inventory, metadata) = fixture();
            set_metadata(&mut inventory, &metadata);
            inventory.entries.remove(path);
            assert!(inspect(&inventory).is_err(), "accepted missing {path}");
        }
    }

    #[test]
    fn accepts_implicit_stdlib_and_rejects_explicit_nondirectory() {
        let (mut inventory, metadata) = fixture();
        set_metadata(&mut inventory, &metadata);
        assert!(inspect(&inventory).is_ok());
        let stdlib = "python/install/lib/python3.13";
        inventory.entries.insert(stdlib.into(), directory());
        assert!(inspect(&inventory).is_ok());
        inventory.entries.insert(stdlib.into(), regular(b"file"));
        assert!(
            inspect(&inventory)
                .unwrap_err()
                .contains("archive directory")
        );
    }

    #[test]
    fn rejects_library_header_disagreement_and_truncation() {
        for (offset, byte) in [(4, 1), (5, 2), (16, 2), (18, 62), (20, 2), (52, 32)] {
            let (mut inventory, metadata) = fixture();
            set_metadata(&mut inventory, &metadata);
            inventory.binary_prefixes.values_mut().next().unwrap()[offset] = byte;
            assert!(inspect(&inventory).unwrap_err().contains("ELF64"));
        }
        let (mut inventory, metadata) = fixture();
        set_metadata(&mut inventory, &metadata);
        inventory
            .binary_prefixes
            .values_mut()
            .next()
            .unwrap()
            .truncate(63);
        assert!(inspect(&inventory).is_err());
    }

    #[test]
    fn rejects_escaping_metadata_paths_and_noninstallation_runtime() {
        for path in [
            "../libpython.so",
            "/libpython.so",
            "install//libpython.so",
            "install/../libpython.so",
            "install\\libpython.so",
            "build/Modules/mathmodule.o",
        ] {
            let (mut inventory, mut metadata) = fixture();
            metadata["build_info"]["core"]["shared_lib"] = json!(path);
            set_metadata(&mut inventory, &metadata);
            assert!(inspect(&inventory).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn follows_only_resolved_archive_file_aliases() {
        let (mut inventory, mut metadata) = fixture();
        let target = "python/install/lib/libpython3.13.so.1.0";
        let alias = "python/install/lib/libpython3.13.so";
        inventory.entries.insert(
            alias.into(),
            Entry {
                kind: EntryKind::Symlink,
                size: 0,
                mode: 0o777,
                sha256: None,
                link_target: Some("libpython3.13.so.1.0".into()),
                resolved_target: Some(target.into()),
            },
        );
        metadata["build_info"]["core"]["shared_lib"] = json!("install/lib/libpython3.13.so");
        set_metadata(&mut inventory, &metadata);
        assert_eq!(
            inspect(&inventory).unwrap().runtime_library.resolved_path,
            target
        );
        inventory.entries.get_mut(alias).unwrap().resolved_target = None;
        assert!(inspect(&inventory).is_err());
        inventory.entries.get_mut(alias).unwrap().resolved_target =
            Some("python/build/Modules/mathmodule.o".into());
        assert!(
            inspect(&inventory)
                .unwrap_err()
                .contains("outside installation")
        );
    }

    #[test]
    fn rejects_ambiguous_missing_or_contradictory_extension_candidates() {
        for mutation in 0..5 {
            let (mut inventory, mut metadata) = fixture();
            let candidates = metadata["build_info"]["extensions"]["math"]
                .as_array_mut()
                .unwrap();
            match mutation {
                0 => {
                    let second = candidates[0].clone();
                    candidates.push(second);
                }
                1 => candidates.clear(),
                2 => candidates[0]["init_fn"] = json!("NULL"),
                3 => candidates[0]["objs"] = json!([]),
                4 => candidates[0]["variant"] = json!("alternate"),
                _ => unreachable!(),
            }
            set_metadata(&mut inventory, &metadata);
            assert!(inspect(&inventory).is_err(), "accepted mutation {mutation}");
        }
    }

    #[test]
    fn rejects_link_declarations_that_need_host_path_fallback() {
        for link in [
            json!({"name":"missing"}),
            json!({"name":"missing","path_dynamic":"install/lib/missing.so"}),
            json!({"name":"/usr/lib/undeclared.so","system":true}),
            json!({"name":"pthread","system":true,"path_static":"build/lib/libssl.a"}),
            json!({"name":"Security","framework":true,"system":true}),
        ] {
            let (mut inventory, mut metadata) = fixture();
            metadata["build_info"]["core"]["links"] = json!([link]);
            set_metadata(&mut inventory, &metadata);
            assert!(inspect(&inventory).is_err());
        }
    }

    #[test]
    fn rejects_missing_metadata_and_unsupported_requested_profile() {
        let (mut inventory, metadata) = fixture();
        assert!(inspect(&inventory).unwrap_err().contains("missing"));
        set_metadata(&mut inventory, &metadata);
        for (version, target, options) in [
            ("3.14.0", "aarch64-unknown-linux-gnu", "pgo+lto"),
            ("3.13.16", "x86_64-unknown-linux-gnu", "pgo+lto"),
            ("3.13.16", "aarch64-unknown-linux-gnu", "pgo"),
        ] {
            assert!(inspect_metadata(&inventory, version, target, options).is_err());
        }
    }
}
