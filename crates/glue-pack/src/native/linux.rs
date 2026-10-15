//! ELF64 dynamic metadata inspection without memory-loader feature restrictions.
use super::{NativeFacts, diagnostic};
use crate::distribution::Result;
use glue_format::DiagnosticCode;
use std::collections::BTreeSet;
fn bad(message: impl Into<String>) -> glue_format::Diagnostic {
    diagnostic(DiagnosticCode::UnsupportedCapability, message)
}
struct Elf<'a>(&'a [u8]);
impl Elf<'_> {
    fn range(&self, o: u64, n: u64) -> Result<&[u8]> {
        let end = o.checked_add(n).ok_or_else(|| bad("ELF range overflow"))?;
        self.0
            .get(
                usize::try_from(o).map_err(|_| bad("ELF offset overflow"))?
                    ..usize::try_from(end).map_err(|_| bad("ELF end overflow"))?,
            )
            .ok_or_else(|| bad("ELF range outside file"))
    }
    fn u16(&self, o: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.range(o, 2)?.try_into().unwrap()))
    }
    fn u32(&self, o: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.range(o, 4)?.try_into().unwrap()))
    }
    fn u64(&self, o: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.range(o, 8)?.try_into().unwrap()))
    }
}
pub fn inspect_bytes(bytes: &[u8]) -> Result<NativeFacts> {
    let e = Elf(bytes);
    if e.range(0, 7)? != b"\x7fELF\x02\x01\x01" {
        return Err(bad("compact Linux requires little-endian ELF64"));
    }
    let architecture = match e.u16(18)? {
        62 => "x86_64",
        183 => "aarch64",
        _ => return Err(bad("unsupported ELF architecture")),
    };
    let kind = match e.u16(16)? {
        2 => "executable",
        3 => "shared",
        _ => return Err(bad("expected ELF executable/shared image")),
    };
    let phoff = e.u64(32)?;
    let phsize = u64::from(e.u16(54)?);
    let count = u64::from(e.u16(56)?);
    if phsize != 56 || count == 0 || count > 4096 {
        return Err(bad("invalid ELF program-header table"));
    }
    e.range(phoff, count * phsize)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut interpreter = None;
    let mut features = BTreeSet::new();
    for i in 0..count {
        let p = phoff + i * phsize;
        let tag = e.u32(p)?;
        let offset = e.u64(p + 8)?;
        let address = e.u64(p + 16)?;
        let filesz = e.u64(p + 32)?;
        let memsz = e.u64(p + 40)?;
        if filesz > memsz {
            return Err(bad("ELF filesz exceeds memsz"));
        }
        e.range(offset, filesz)?;
        match tag {
            1 => loads.push((address, offset, filesz)),
            2 => {
                if dynamic.replace((offset, filesz)).is_some() {
                    return Err(bad("duplicate ELF dynamic segment"));
                }
            }
            3 => {
                let s = e.range(offset, filesz)?;
                interpreter = Some(cstring(s, 0)?);
            }
            7 => {
                features.insert("tls".into());
            }
            0x6474e550 => {
                features.insert("unwind".into());
            }
            0x6474e553 => {
                features.insert("gnu_property".into());
            }
            _ => (),
        }
    }
    let mapped = |address: u64, size: u64| -> Result<u64> {
        for (base, offset, length) in &loads {
            if address >= *base
                && address
                    .checked_sub(*base)
                    .and_then(|n| n.checked_add(size))
                    .is_some_and(|n| n <= *length)
            {
                return Ok(offset + (address - base));
            }
        }
        Err(bad("ELF dynamic address is not file-backed"))
    };
    let (offset, size) = dynamic.ok_or_else(|| bad("ELF image has no dynamic metadata"))?;
    if size % 16 != 0 || size / 16 > 65536 {
        return Err(bad("invalid ELF dynamic segment size"));
    }
    let mut tags = std::collections::BTreeMap::<u64, Vec<u64>>::new();
    let mut terminated = false;
    for i in 0..size / 16 {
        let tag = e.u64(offset + i * 16)?;
        let value = e.u64(offset + i * 16 + 8)?;
        if tag == 0 {
            terminated = true;
            break;
        }
        tags.entry(tag).or_default().push(value);
    }
    if !terminated {
        return Err(bad("unterminated ELF dynamic segment"));
    }
    let single = |tag: u64| -> Result<Option<u64>> {
        match tags.get(&tag) {
            None => Ok(None),
            Some(v) if v.len() == 1 => Ok(Some(v[0])),
            _ => Err(bad("duplicate singleton ELF dynamic tag")),
        }
    };
    let strsz = single(10)?.ok_or_else(|| bad("missing ELF string table size"))?;
    if strsz > 32 * 1024 * 1024 {
        return Err(bad("ELF string table exceeds bound"));
    }
    let strtab = mapped(
        single(5)?.ok_or_else(|| bad("missing ELF string table"))?,
        strsz,
    )?;
    let strings = e.range(strtab, strsz)?;
    let dependencies = tags
        .get(&1)
        .into_iter()
        .flatten()
        .map(|o| cstring(strings, *o))
        .collect::<Result<Vec<_>>>()?;
    let identity = single(14)?.map(|o| cstring(strings, o)).transpose()?;
    let paths = single(29)?
        .or(single(15)?)
        .map(|o| cstring(strings, o))
        .transpose()?
        .unwrap_or_default();
    let search_paths = if paths.is_empty() {
        Vec::new()
    } else {
        paths.split(':').map(str::to_owned).collect()
    };
    if tags.contains_key(&0x6ffffef5) {
        features.insert("gnu_hash".into());
    }
    if tags.contains_key(&12) || tags.contains_key(&25) {
        features.insert("constructors".into());
    }
    let mut versions = BTreeSet::new();
    if let Some(base) = single(0x6ffffffe)? {
        let count =
            single(0x6fffffff)?.ok_or_else(|| bad("missing ELF version requirement count"))?;
        if count > 4096 {
            return Err(bad("ELF version count exceeds bound"));
        }
        let mut current = base;
        for i in 0..count {
            let p = mapped(current, 16)?;
            if e.u16(p)? != 1 {
                return Err(bad("unsupported ELF version structure"));
            }
            let aux_count = u64::from(e.u16(p + 2)?);
            if aux_count > 4096 {
                return Err(bad("ELF version aux count exceeds bound"));
            }
            let mut aux = current
                .checked_add(u64::from(e.u32(p + 8)?))
                .ok_or_else(|| bad("version pointer overflow"))?;
            for j in 0..aux_count {
                let a = mapped(aux, 16)?;
                versions.insert(cstring(strings, u64::from(e.u32(a + 8)?))?);
                let next = u64::from(e.u32(a + 12)?);
                if j + 1 < aux_count && next < 16 {
                    return Err(bad("invalid ELF version auxiliary chain"));
                }
                aux = aux
                    .checked_add(next)
                    .ok_or_else(|| bad("version chain overflow"))?;
            }
            let next = u64::from(e.u32(p + 12)?);
            if i + 1 < count && next < 16 {
                return Err(bad("invalid ELF version chain"));
            }
            current = current
                .checked_add(next)
                .ok_or_else(|| bad("version chain overflow"))?;
        }
    }
    Ok(NativeFacts {
        format: "elf".into(),
        architecture: architecture.into(),
        kind: kind.into(),
        dependencies,
        identity,
        search_paths,
        minimum_os: None,
        versions,
        features,
        interpreter,
    })
}
fn cstring(bytes: &[u8], offset: u64) -> Result<String> {
    let start = usize::try_from(offset).map_err(|_| bad("ELF string offset overflow"))?;
    let rest = bytes
        .get(start..)
        .ok_or_else(|| bad("ELF string outside table"))?;
    let end = rest
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| bad("unterminated ELF string"))?;
    if end > 64 * 1024 {
        return Err(bad("ELF string exceeds bound"));
    }
    std::str::from_utf8(&rest[..end])
        .map(str::to_owned)
        .map_err(|_| bad("ELF string is not UTF8"))
}

/// Opt-in metadata edits use an explicitly provisioned build tool, never a runtime installer.
pub(crate) fn normalize_collection(collection: &mut super::NativeCollection) -> Result<()> {
    use crate::distribution::PayloadSource;
    use glue_format::{DependencyProvider, InputIdentity, Transformation};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    for (source, deployed) in &collection.mappings {
        let facts = &collection.facts[deployed];
        let parent = Path::new(deployed).parent().unwrap();
        let mut rpaths: BTreeSet<String> = facts
            .search_paths
            .iter()
            .filter(|p| p.starts_with("$ORIGIN") || p.starts_with("${ORIGIN}"))
            .cloned()
            .collect();
        let mut replacements = Vec::new();
        for edge in collection.inventory.edges.iter().filter(|e| {
            &e.from == deployed
                && matches!(
                    e.provider,
                    DependencyProvider::Bundled | DependencyProvider::Runtime
                )
        }) {
            let relative =
                super::relative_path(parent, Path::new(&edge.resolved).parent().unwrap());
            rpaths.insert(if relative.is_empty() {
                "$ORIGIN".into()
            } else {
                format!("$ORIGIN/{relative}")
            });
            if edge.name.contains('/') {
                replacements.push((
                    edge.name.clone(),
                    Path::new(&edge.resolved)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                ));
            }
        }
        let desired = rpaths.into_iter().collect::<Vec<_>>().join(":");
        let change_paths = desired != facts.search_paths.join(":");
        let soname = facts
            .identity
            .as_ref()
            .filter(|id| id.contains('/'))
            .map(|_| {
                Path::new(deployed)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            });
        if !change_paths && replacements.is_empty() && soname.is_none() {
            continue;
        }
        if !cfg!(target_os = "linux") {
            return Err(super::diagnostic(
                DiagnosticCode::UnsupportedCapability,
                "ELF path normalization must execute on Linux with patchelf",
            ));
        }
        let tool = std::env::var_os("GLUE_PATCHELF")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/bin/patchelf"));
        if !tool.is_absolute() || !tool.is_file() {
            return Err(super::diagnostic(
                DiagnosticCode::TransformationRequired,
                format!(
                    "{deployed}: propose RUNPATH={desired:?}, needed edits={replacements:?}; provision patchelf at build time and set GLUE_PATCHELF to its absolute path"
                ),
            ));
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = Temporary(std::env::temp_dir().join(format!(
            "glue-elf-normalize-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir(&directory.0).map_err(|e| bad(e.to_string()))?;
        let path = directory.0.join("image");
        fs::copy(source, &path).map_err(|e| bad(e.to_string()))?;
        let input = super::read_image(source)?;
        let mut command = Command::new(&tool);
        let mut edits = Vec::new();
        if change_paths {
            command.args(["--set-rpath", &desired]);
            edits.push(format!("RUNPATH -> {desired}"));
        }
        if let Some(name) = &soname {
            command.args(["--set-soname", name]);
            edits.push(format!("SONAME -> {name}"));
        }
        for (old, new) in &replacements {
            command.args(["--replace-needed", old, new]);
            edits.push(format!("NEEDED {old} -> {new}"));
        }
        let status = command
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| bad(format!("patchelf: {e}")))?;
        if !status.success() {
            return Err(super::diagnostic(
                DiagnosticCode::TransformationRequired,
                format!("patchelf failed to apply previewed edits for {deployed}"),
            ));
        }
        let output = super::read_image(&path)?;
        let after = inspect_bytes(&output)?;
        let expected = facts
            .dependencies
            .iter()
            .map(|d| {
                replacements
                    .iter()
                    .find(|(old, _)| old == d)
                    .map(|(_, new)| new)
                    .unwrap_or(d)
                    .clone()
            })
            .collect::<Vec<_>>();
        if after.architecture != facts.architecture
            || after.kind != facts.kind
            || after.dependencies != expected
            || after.search_paths.join(":") != desired
            || facts
                .features
                .iter()
                .filter(|f| ["tls", "unwind", "gnu_hash"].contains(&f.as_str()))
                .any(|f| !after.features.contains(f))
        {
            return Err(bad(
                "ELF normalization failed independent metadata verification",
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(source)
            .map_err(|e| bad(e.to_string()))?
            .permissions()
            .mode()
            & 0o777;
        collection.inventory.transformations.push(Transformation {
            path: deployed.clone(),
            input: InputIdentity::of(&input),
            output: InputIdentity::of(&output),
            edits,
            signing: None,
        });
        collection.payloads.insert(
            deployed.clone(),
            PayloadSource::Bytes {
                bytes: output,
                mode,
            },
        );
    }
    Ok(())
}
