//! Portable admission checks for the bounded GNU Linux AArch64 fixture profile.
//!
//! This is deliberately not a general ELF parser. Program headers and dynamic
//! tables describe the admitted image; section headers are never consulted.
//! Inspection performs no mapping, loader operation, or constructor call.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const MAX_ELF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SYMBOLS: usize = 65_536;
pub const MAX_RELOCATIONS: usize = 65_536;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_DYNAMIC_ENTRIES: usize = 4096;
const MAX_VERSION_REQUIREMENTS: usize = 1024;
const MAX_IMAGE_SPAN: u64 = 256 * 1024 * 1024;

/// Only these compiler hooks may be undeclared, and only as unversioned weak
/// undefined NOTYPE symbols. Other imports must be explicitly supplied.
pub const GNU_WEAK_IMPORTS: [&str; 3] = [
    "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable",
    "__gmon_start__",
];

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_PLTGOT: u64 = 3;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_SONAME: u64 = 14;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_BIND_NOW: u64 = 24;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_FLAGS: u64 = 30;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_RELACOUNT: u64 = 0x6fff_fff9;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElfError {
    Invalid(String),
    Unsupported(String),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid ELF: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported ELF profile: {message}"),
        }
    }
}

impl Error for ElfError {}

type Result<T> = std::result::Result<T, ElfError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    NoType,
    Object,
    Function,
    /// GNU linkers include unnamed local section markers in DT_HASH's count.
    Section,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSymbol {
    pub index: usize,
    pub name: String,
    pub binding: SymbolBinding,
    pub kind: SymbolKind,
    pub defined: bool,
    pub value: u64,
    pub size: u64,
    pub visibility: u8,
    pub version_index: u16,
    pub version_hidden: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTable {
    Rela,
    Plt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relocation {
    pub offset: u64,
    pub kind: u32,
    pub symbol_index: usize,
    pub addend: i64,
    pub table: RelocationTable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRequirement {
    pub library: String,
    pub name: String,
    pub index: u16,
    pub flags: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfFacts {
    pub soname: String,
    pub needed: Vec<String>,
    pub has_constructors: bool,
    /// Includes the required all-zero entry at index zero.
    pub symbols: Vec<DynamicSymbol>,
    pub relocations: Vec<Relocation>,
    pub version_requirements: Vec<VersionRequirement>,
    pub load_segments: Vec<LoadSegment>,
}

impl ElfFacts {
    pub fn symbol(&self, name: &str) -> Option<&DynamicSymbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }

    pub fn contains_executable_address(&self, address: u64) -> bool {
        self.load_segments
            .iter()
            .any(|segment| segment.flags & PF_X != 0 && contains(segment, address, 1))
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(ElfError::Invalid(message.into()))
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(ElfError::Unsupported(message.into()))
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| ElfError::Invalid("offset/address overflow".into()))
}

fn bytes_at(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = add(offset, size)?;
    let start = usize::try_from(offset)
        .map_err(|_| ElfError::Invalid("offset exceeds host address size".into()))?;
    let end = usize::try_from(end)
        .map_err(|_| ElfError::Invalid("range exceeds host address size".into()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| ElfError::Invalid("truncated file range".into()))
}

fn u16_at(bytes: &[u8], offset: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes_at(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes_at(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes_at(bytes, offset, 8)?.try_into().unwrap(),
    ))
}

fn contains(segment: &LoadSegment, address: u64, size: u64) -> bool {
    address >= segment.virtual_address
        && address.checked_add(size).is_some_and(|end| {
            segment
                .virtual_address
                .checked_add(segment.memory_size)
                .is_some_and(|limit| end <= limit)
        })
}

struct Image<'a> {
    bytes: &'a [u8],
    loads: Vec<LoadSegment>,
    /// Disjoint metadata ranges. Initializer arrays are separately checked because
    /// their elements are legitimate relocation targets.
    metadata: Vec<(u64, u64)>,
}

impl<'a> Image<'a> {
    fn file_offset(&self, address: u64, size: u64) -> Result<u64> {
        let end = add(address, size)?;
        for load in &self.loads {
            let file_end = add(load.virtual_address, load.file_size)?;
            if load.flags & PF_R != 0 && address >= load.virtual_address && end <= file_end {
                return add(load.file_offset, address - load.virtual_address);
            }
        }
        invalid("dynamic address is outside a readable file-backed load segment")
    }

    fn read(&self, address: u64, size: u64) -> Result<&'a [u8]> {
        bytes_at(self.bytes, self.file_offset(address, size)?, size)
    }

    fn table(&mut self, address: u64, size: u64, alignment: u64) -> Result<&'a [u8]> {
        if size == 0 || address % alignment != 0 {
            return invalid("empty or misaligned dynamic table");
        }
        let offset = self.file_offset(address, size)?;
        let end = add(offset, size)?;
        if self
            .metadata
            .iter()
            .any(|&(start, limit)| offset < limit && start < end)
        {
            return invalid("overlapping dynamic metadata tables");
        }
        self.metadata.push((offset, end));
        bytes_at(self.bytes, offset, size)
    }

    fn writable(&self, address: u64, size: u64) -> bool {
        self.loads
            .iter()
            .any(|load| load.flags & (PF_W | PF_X) == PF_W && contains(load, address, size))
    }

    fn executable(&self, address: u64) -> bool {
        self.loads
            .iter()
            .any(|load| load.flags & PF_X != 0 && contains(load, address, 1))
    }
}

fn name_at(strings: &[u8], offset: u64, budget: &mut usize) -> Result<String> {
    let start =
        usize::try_from(offset).map_err(|_| ElfError::Invalid("string offset overflow".into()))?;
    let tail = strings
        .get(start..)
        .ok_or_else(|| ElfError::Invalid("string offset outside DT_STRTAB".into()))?;
    let length = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| ElfError::Invalid("unterminated dynamic string".into()))?;
    if length > MAX_NAME_BYTES {
        return unsupported("dynamic name exceeds the fixture name limit");
    }
    if tail[..length]
        .iter()
        .any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return unsupported("dynamic names must be printable non-space ASCII");
    }
    *budget = budget
        .checked_add(length)
        .ok_or_else(|| ElfError::Invalid("metadata accounting overflow".into()))?;
    if *budget > MAX_METADATA_BYTES {
        return unsupported("owned dynamic metadata exceeds the fixture limit");
    }
    Ok(String::from_utf8(tail[..length].to_vec()).unwrap())
}

fn basename(name: &str) -> Result<()> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\']) {
        return unsupported("SONAME/NEEDED entries must be nonempty library basenames");
    }
    Ok(())
}

fn required(tags: &BTreeMap<u64, u64>, tag: u64) -> Result<u64> {
    tags.get(&tag)
        .copied()
        .ok_or_else(|| ElfError::Invalid(format!("missing dynamic tag {tag:#x}")))
}

fn paired(tags: &BTreeMap<u64, u64>, pointer: u64, size: u64) -> Result<Option<(u64, u64)>> {
    match (tags.get(&pointer), tags.get(&size)) {
        (None, None) => Ok(None),
        (Some(&address), Some(&length)) if length > 0 => Ok(Some((address, length))),
        _ => invalid("inconsistent dynamic pointer/count tags"),
    }
}

/// Inspect an image before creating any memfd or invoking the OS loader. The
/// supplied import set is the already selected manifest/runtime/OS policy.
pub fn inspect(
    bytes: &[u8],
    expected_soname: &str,
    allowed_undefined: &BTreeSet<String>,
) -> Result<ElfFacts> {
    if bytes.len() > MAX_ELF_BYTES {
        return unsupported("image exceeds the fixture byte limit");
    }
    let header = bytes_at(bytes, 0, 64)?;
    if &header[..4] != b"\x7fELF" {
        return invalid("missing ELF magic");
    }
    if header[4] != 2 || header[5] != 1 || !matches!(header[7], 0 | 3) || header[8] != 0 {
        return unsupported("require ELF64 little-endian System V/Linux ABI");
    }
    if header[6] != 1 || header[9..16].iter().any(|&byte| byte != 0) || u32_at(header, 20)? != 1 {
        return invalid("invalid ELF identification/version");
    }
    if u16_at(header, 16)? != 3 || u16_at(header, 18)? != 183 {
        return unsupported("require ET_DYN AArch64");
    }
    if u64_at(header, 24)? != 0 || u32_at(header, 48)? != 0 {
        return unsupported("shared image entry point or architecture flags");
    }
    if u16_at(header, 52)? != 64 || u16_at(header, 54)? != 56 {
        return invalid("unexpected ELF/program-header size");
    }
    let count = u16_at(header, 56)? as usize;
    let offset = u64_at(header, 32)?;
    if count == 0 || count > 128 || offset < 64 || offset % 8 != 0 {
        return invalid("invalid program-header count/offset");
    }
    let phdrs = bytes_at(bytes, offset, (count * 56) as u64)?;
    let mut loads = Vec::new();
    let mut auxiliary = Vec::new();
    let mut dynamic = None;
    let mut stack_seen = false;
    for phdr in phdrs.chunks_exact(56) {
        let kind = u32_at(phdr, 0)?;
        let flags = u32_at(phdr, 4)?;
        let file_offset = u64_at(phdr, 8)?;
        let address = u64_at(phdr, 16)?;
        let file_size = u64_at(phdr, 32)?;
        let memory_size = u64_at(phdr, 40)?;
        let alignment = u64_at(phdr, 48)?;
        if flags & !7 != 0 || flags & (PF_W | PF_X) == PF_W | PF_X {
            return unsupported("unknown segment permissions or writable executable segment");
        }
        if file_size > memory_size {
            return invalid("segment file size exceeds memory size");
        }
        bytes_at(bytes, file_offset, file_size)?;
        add(address, memory_size)?;
        if alignment > 1
            && (!alignment.is_power_of_two() || address % alignment != file_offset % alignment)
        {
            return invalid("invalid segment alignment/congruence");
        }
        match kind {
            PT_LOAD => {
                if memory_size == 0 || flags & PF_R == 0 || !(4096..=65_536).contains(&alignment) {
                    return unsupported("unsupported load segment size, permissions or alignment");
                }
                loads.push(LoadSegment {
                    virtual_address: address,
                    memory_size,
                    file_offset,
                    file_size,
                    flags,
                });
            }
            PT_DYNAMIC => {
                if dynamic.replace((file_offset, address, file_size)).is_some() {
                    return invalid("multiple PT_DYNAMIC segments");
                }
                if flags != PF_R | PF_W
                    || file_size != memory_size
                    || file_size % 16 != 0
                    || file_size == 0
                    || file_size / 16 > MAX_DYNAMIC_ENTRIES as u64
                {
                    return invalid("invalid PT_DYNAMIC bounds/permissions");
                }
            }
            PT_GNU_STACK => {
                if stack_seen || flags != PF_R | PF_W || file_size != 0 || memory_size != 0 {
                    return unsupported("require exactly one non-executable GNU stack declaration");
                }
                stack_seen = true;
            }
            // Known auxiliary metadata stays inside existing load ranges.
            6 | 4 | 0x6474_e550 | 0x6474_e552 => {
                if flags != PF_R || file_size == 0 || file_size != memory_size {
                    return unsupported("unsupported auxiliary segment permissions/size");
                }
                auxiliary.push((kind, file_offset, address, file_size));
                // GNU property notes would enable unimplemented architecture features.
                if kind == 4 {
                    check_notes(bytes_at(bytes, file_offset, file_size)?)?;
                }
            }
            _ => return unsupported(format!("program-header type {kind:#x}")),
        }
    }
    if !stack_seen || loads.is_empty() {
        return unsupported("require load segments and an explicit non-executable GNU stack");
    }
    loads.sort_by_key(|load| load.virtual_address);
    if loads[0].virtual_address != 0
        || loads[0].file_offset != 0
        || loads[0].file_size < add(offset, (count * 56) as u64)?
    {
        return unsupported(
            "first load segment must contain the ELF and program headers at image base zero",
        );
    }
    for pair in loads.windows(2) {
        if add(pair[0].virtual_address, pair[0].memory_size)? > pair[1].virtual_address {
            return invalid("overlapping load virtual ranges");
        }
        if add(add(pair[0].virtual_address, pair[0].memory_size)?, 4095)? & !4095
            > pair[1].virtual_address & !4095
        {
            return unsupported("load segments overlap at the declared 4096-byte page size");
        }
    }
    for (i, first) in loads.iter().enumerate() {
        for second in &loads[i + 1..] {
            if first.file_offset < add(second.file_offset, second.file_size)?
                && second.file_offset < add(first.file_offset, first.file_size)?
            {
                return invalid("overlapping load file ranges");
            }
        }
    }
    let image_end = add(
        loads.last().unwrap().virtual_address,
        loads.last().unwrap().memory_size,
    )?;
    if image_end - loads[0].virtual_address > MAX_IMAGE_SPAN {
        return unsupported("load span exceeds the fixture limit");
    }
    let mut image = Image {
        bytes,
        loads,
        metadata: Vec::new(),
    };
    for (kind, file_offset, address, size) in auxiliary {
        if image.file_offset(address, size)? != file_offset {
            return invalid("auxiliary segment does not match its load mapping");
        }
        if kind == 0x6474_e552 && !image.writable(address, size) {
            return invalid("GNU_RELRO must cover writable non-executable load memory");
        }
    }
    let (dynamic_offset, dynamic_address, dynamic_size) =
        dynamic.ok_or_else(|| ElfError::Invalid("missing PT_DYNAMIC".into()))?;
    if image.file_offset(dynamic_address, dynamic_size)? != dynamic_offset
        || !image.writable(dynamic_address, dynamic_size)
    {
        return invalid("PT_DYNAMIC does not match its load-segment mapping");
    }
    let entries = image.table(dynamic_address, dynamic_size, 8)?;
    let mut tags = BTreeMap::new();
    let mut needed_offsets = Vec::new();
    let mut terminated = false;
    for entry in entries.chunks_exact(16) {
        let tag = u64_at(entry, 0)?;
        let value = u64_at(entry, 8)?;
        if tag == DT_NULL {
            if value != 0 {
                return invalid("nonzero DT_NULL value");
            }
            terminated = true;
            continue;
        }
        if terminated {
            return invalid("dynamic data after DT_NULL");
        }
        if tag == DT_NEEDED {
            if needed_offsets.len() == 64 {
                return unsupported("too many NEEDED entries");
            }
            needed_offsets.push(value);
            continue;
        }
        if !matches!(
            tag,
            DT_PLTRELSZ
                | DT_PLTGOT
                | DT_HASH
                | DT_STRTAB
                | DT_SYMTAB
                | DT_RELA
                | DT_RELASZ
                | DT_RELAENT
                | DT_STRSZ
                | DT_SYMENT
                | DT_INIT
                | DT_FINI
                | DT_SONAME
                | DT_PLTREL
                | DT_JMPREL
                | DT_BIND_NOW
                | DT_INIT_ARRAY
                | DT_FINI_ARRAY
                | DT_INIT_ARRAYSZ
                | DT_FINI_ARRAYSZ
                | DT_FLAGS
                | DT_VERSYM
                | DT_RELACOUNT
                | DT_FLAGS_1
                | DT_VERNEED
                | DT_VERNEEDNUM
        ) {
            return unsupported(format!(
                "dynamic tag {tag:#x} (REL/TLS/search paths/auditing and other extensions are not admitted)"
            ));
        }
        if tags.insert(tag, value).is_some() {
            return invalid(format!("duplicate dynamic tag {tag:#x}"));
        }
    }
    if !terminated {
        return invalid("unterminated PT_DYNAMIC");
    }
    let flags = tags.get(&DT_FLAGS).copied().unwrap_or(0);
    let flags1 = tags.get(&DT_FLAGS_1).copied().unwrap_or(0);
    if flags & !8 != 0
        || flags1 & !1 != 0
        || tags.get(&DT_BIND_NOW).is_some_and(|&value| value != 0)
    {
        return unsupported("dynamic flags outside immediate binding");
    }
    if flags & 8 == 0 && flags1 & 1 == 0 && !tags.contains_key(&DT_BIND_NOW) {
        return unsupported("immediate binding is required");
    }
    let string_size = required(&tags, DT_STRSZ)?;
    if string_size > MAX_METADATA_BYTES as u64 {
        return unsupported("dynamic string table exceeds the fixture limit");
    }
    let strings = image.table(required(&tags, DT_STRTAB)?, string_size, 1)?;
    if strings.first() != Some(&0) || strings.last() != Some(&0) {
        return invalid("invalid dynamic string-table boundary");
    }
    let mut budget = 0;
    let soname = name_at(strings, required(&tags, DT_SONAME)?, &mut budget)?;
    basename(&soname)?;
    if soname != expected_soname {
        return invalid(format!(
            "SONAME {soname:?} does not match {expected_soname:?}"
        ));
    }
    let mut needed = Vec::new();
    let mut seen_needed = BTreeSet::new();
    for offset in needed_offsets {
        let name = name_at(strings, offset, &mut budget)?;
        basename(&name)?;
        if name == soname || !seen_needed.insert(name.clone()) {
            return invalid("self or duplicate NEEDED entry");
        }
        needed.push(name);
    }
    let hash_address = required(&tags, DT_HASH)?;
    let hash_header = image.read(hash_address, 8)?;
    let buckets = u32_at(hash_header, 0)? as usize;
    let symbols = u32_at(hash_header, 4)? as usize;
    if buckets == 0 || buckets > MAX_SYMBOLS || symbols == 0 || symbols > MAX_SYMBOLS {
        return unsupported("SysV hash count exceeds the fixture limit or is empty");
    }
    let hash = image.table(hash_address, (8 + 4 * (buckets + symbols)) as u64, 4)?;
    if required(&tags, DT_SYMENT)? != 24 {
        return invalid("DT_SYMENT must be 24");
    }
    let symtab = image.table(required(&tags, DT_SYMTAB)?, (symbols * 24) as u64, 8)?;
    let version_requirements = parse_versions(&mut image, &tags, strings, &needed, &mut budget)?;
    let version_indexes: BTreeSet<u16> = version_requirements
        .iter()
        .map(|version| version.index)
        .collect();
    let versym = if let Some(&address) = tags.get(&DT_VERSYM) {
        Some(image.table(address, (symbols * 2) as u64, 2)?)
    } else {
        None
    };
    if !version_requirements.is_empty() && versym.is_none() {
        return invalid("version requirements without DT_VERSYM");
    }
    let mut names = BTreeSet::new();
    let mut dynamic_symbols = Vec::with_capacity(symbols);
    for (index, symbol) in symtab.chunks_exact(24).enumerate() {
        if index == 0 && symbol.iter().any(|&byte| byte != 0) {
            return invalid("dynamic symbol zero is not all zero");
        }
        let name = name_at(strings, u32_at(symbol, 0)? as u64, &mut budget)?;
        let binding = match symbol[4] >> 4 {
            0 => SymbolBinding::Local,
            1 => SymbolBinding::Global,
            2 => SymbolBinding::Weak,
            _ => return unsupported("symbol binding (including GNU_UNIQUE)"),
        };
        let kind = match symbol[4] & 15 {
            0 => SymbolKind::NoType,
            1 => SymbolKind::Object,
            2 => SymbolKind::Function,
            3 => SymbolKind::Section,
            _ => return unsupported("symbol kind (including TLS/IFUNC)"),
        };
        let visibility = symbol[5];
        if visibility != 0 {
            return unsupported("non-default symbol visibility/architecture bits");
        }
        let section = u16_at(symbol, 6)?;
        if section >= 0xff00 {
            return unsupported("reserved/extended/absolute symbol section index");
        }
        let defined = section != 0;
        let value = u64_at(symbol, 8)?;
        let size = u64_at(symbol, 16)?;
        if kind == SymbolKind::Section {
            if !defined
                || binding != SymbolBinding::Local
                || !name.is_empty()
                || u32_at(symbol, 0)? != 0
                || size != 0
            {
                return invalid("section symbol must be an unnamed, zero-sized local definition");
            }
        } else if index != 0 && (name.is_empty() || !names.insert(name.clone())) {
            return invalid("empty or duplicate dynamic symbol name");
        }
        let version = versym
            .map(|table| u16_at(table, (index * 2) as u64))
            .transpose()?
            .unwrap_or(if binding == SymbolBinding::Local {
                0
            } else {
                1
            });
        let version_index = version & 0x7fff;
        let version_hidden = version & 0x8000 != 0;
        if version_hidden
            || (version_index > 1 && (!version_indexes.contains(&version_index) || defined))
        {
            return unsupported("hidden or undefined symbol-version index");
        }
        if (binding == SymbolBinding::Local) != (version_index == 0) {
            return invalid("symbol binding/version-local mismatch");
        }
        if defined {
            let extent = size.max(1);
            if !image.loads.iter().any(|load| contains(load, value, extent)) {
                return invalid("defined symbol lies outside load memory");
            }
            if kind == SymbolKind::Function && value % 4 != 0 {
                return invalid("AArch64 function symbol must be 4-byte aligned");
            }
            if kind == SymbolKind::Function
                && !image
                    .loads
                    .iter()
                    .any(|load| load.flags & PF_X != 0 && contains(load, value, extent))
            {
                return invalid("function symbol lies outside executable memory");
            }
        } else if value != 0 || size != 0 {
            return invalid("undefined symbol has nonzero value/size");
        }
        if index != 0 && !defined {
            let compiler_hook = binding == SymbolBinding::Weak
                && kind == SymbolKind::NoType
                && version_index == 1
                && GNU_WEAK_IMPORTS.contains(&name.as_str());
            if !compiler_hook && !allowed_undefined.contains(&name) {
                return invalid(format!("undeclared undefined symbol {name:?}"));
            }
            if binding == SymbolBinding::Local || kind == SymbolKind::Object {
                return unsupported("local/object undefined import");
            }
        }
        dynamic_symbols.push(DynamicSymbol {
            index,
            name,
            binding,
            kind,
            defined,
            value,
            size,
            visibility,
            version_index,
            version_hidden,
        });
    }
    validate_hash(hash, buckets, &dynamic_symbols)?;
    let mut relocations = Vec::new();
    if let Some((address, size)) = paired(&tags, DT_RELA, DT_RELASZ)? {
        if required(&tags, DT_RELAENT)? != 24 {
            return invalid("DT_RELAENT must be 24");
        }
        parse_relocations(
            &mut image,
            address,
            size,
            RelocationTable::Rela,
            &dynamic_symbols,
            &mut relocations,
        )?;
    } else if tags.contains_key(&DT_RELAENT) || tags.contains_key(&DT_RELACOUNT) {
        return invalid("RELA entry/count metadata without a RELA table");
    }
    if let Some((address, size)) = paired(&tags, DT_JMPREL, DT_PLTRELSZ)? {
        required(&tags, DT_PLTGOT)?;
        if required(&tags, DT_PLTREL)? != DT_RELA {
            return unsupported("PLT relocations must use RELA");
        }
        parse_relocations(
            &mut image,
            address,
            size,
            RelocationTable::Plt,
            &dynamic_symbols,
            &mut relocations,
        )?;
    } else if tags.contains_key(&DT_PLTREL) {
        return invalid("DT_PLTREL without a PLT relocation table");
    }
    if let Some(&count) = tags.get(&DT_RELACOUNT) {
        let rela: Vec<_> = relocations
            .iter()
            .filter(|relocation| relocation.table == RelocationTable::Rela)
            .collect();
        if count > rela.len() as u64
            || rela[..count as usize]
                .iter()
                .any(|relocation| relocation.kind != 1027)
        {
            return invalid("DT_RELACOUNT does not describe leading RELATIVE relocations");
        }
    }
    if let Some(&address) = tags.get(&DT_PLTGOT) {
        if address % 8 != 0 || !image.writable(address, 24) {
            return invalid("PLTGOT outside aligned writable memory");
        }
        // glibc owns these three control slots; ordinary relocations and
        // initializer arrays may not alias them.
        image.table(address, 24, 8)?;
    }
    let mut targets = BTreeSet::new();
    for relocation in &relocations {
        if !targets.insert(relocation.offset) {
            return invalid("duplicate relocation target");
        }
        if let Ok(offset) = image.file_offset(relocation.offset, 8) {
            if image
                .metadata
                .iter()
                .any(|&(start, end)| offset < end && start < offset + 8)
            {
                return invalid("relocation modifies dynamic inspection metadata");
            }
        }
    }
    for tag in [DT_INIT, DT_FINI] {
        if let Some(&address) = tags.get(&tag) {
            if address == 0 || address % 4 != 0 || !image.executable(address) {
                return invalid("INIT/FINI target outside executable memory");
            }
        }
    }
    check_initializer_array(&image, &tags, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, &relocations)?;
    check_initializer_array(&image, &tags, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, &relocations)?;
    let has_constructors = tags.contains_key(&DT_INIT) || tags.contains_key(&DT_INIT_ARRAY);
    Ok(ElfFacts {
        soname,
        needed,
        has_constructors,
        symbols: dynamic_symbols,
        relocations,
        version_requirements,
        load_segments: image.loads,
    })
}

fn check_notes(notes: &[u8]) -> Result<()> {
    if notes.len() > 4096 {
        return unsupported("note segment exceeds the fixture limit");
    }
    let mut offset = 0u64;
    while offset < notes.len() as u64 {
        let header = bytes_at(notes, offset, 12)?;
        let namesz = u32_at(header, 0)? as u64;
        let descsz = u32_at(header, 4)? as u64;
        let kind = u32_at(header, 8)?;
        let name_start = add(offset, 12)?;
        let name = bytes_at(notes, name_start, namesz)?;
        let desc_start = add(name_start, add(namesz, 3)? & !3)?;
        bytes_at(notes, desc_start, descsz)?;
        offset = add(desc_start, add(descsz, 3)? & !3)?;
        if name != b"GNU\0" || kind != 3 || descsz == 0 || descsz > 64 {
            return unsupported("only bounded GNU build-id notes are admitted");
        }
    }
    if offset != notes.len() as u64 {
        return invalid("note padding exceeds segment bounds");
    }
    Ok(())
}

fn elf_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for byte in name.bytes() {
        hash = (hash << 4).wrapping_add(byte as u32);
        let high = hash & 0xf000_0000;
        hash ^= high >> 24;
        hash &= !high;
    }
    hash
}

fn validate_hash(hash: &[u8], buckets: usize, symbols: &[DynamicSymbol]) -> Result<()> {
    let chain_base = 8 + buckets * 4;
    let chain =
        |index: usize| u32_at(hash, (chain_base + index * 4) as u64).map(|value| value as usize);
    for index in 0..symbols.len() {
        if chain(index)? >= symbols.len() {
            return invalid("SysV hash chain index outside dynamic symbols");
        }
    }
    if chain(0)? != 0 {
        return invalid("SysV hash chain zero must terminate");
    }
    let mut visited = BTreeSet::new();
    for bucket in 0..buckets {
        let mut index = u32_at(hash, (8 + bucket * 4) as u64)? as usize;
        while index != 0 {
            if index >= symbols.len() || !visited.insert(index) {
                return invalid("SysV hash index, cycle or shared bucket chain");
            }
            if elf_hash(&symbols[index].name) as usize % buckets != bucket {
                return invalid("SysV hash symbol is in the wrong bucket");
            }
            index = chain(index)?;
        }
    }
    for symbol in symbols.iter().skip(1) {
        if symbol.defined
            && symbol.binding != SymbolBinding::Local
            && !visited.contains(&symbol.index)
        {
            return invalid("exported symbol missing from SysV hash buckets");
        }
    }
    // Unreachable chains must also terminate; a loader or later lookup must not
    // encounter malformed metadata merely because this fixture does not use it.
    let mut finished = BTreeSet::from([0usize]);
    for index in 1..symbols.len() {
        let mut active = BTreeSet::new();
        let mut cursor = index;
        while !finished.contains(&cursor) {
            if !active.insert(cursor) {
                return invalid("cycle in unreachable SysV hash chain");
            }
            cursor = chain(cursor)?;
        }
        finished.extend(active);
    }
    Ok(())
}

fn parse_versions(
    image: &mut Image<'_>,
    tags: &BTreeMap<u64, u64>,
    strings: &[u8],
    needed: &[String],
    budget: &mut usize,
) -> Result<Vec<VersionRequirement>> {
    let Some((mut address, count)) = paired(tags, DT_VERNEED, DT_VERNEEDNUM)? else {
        return Ok(Vec::new());
    };
    if count > 64 {
        return unsupported("too many version-need records");
    }
    let mut versions = Vec::new();
    let mut indexes = BTreeSet::new();
    let mut libraries = BTreeSet::new();
    for index in 0..count {
        let record = image.table(address, 16, 4)?;
        if u16_at(record, 0)? != 1 {
            return unsupported("unsupported version-need revision");
        }
        let aux_count = u16_at(record, 2)? as usize;
        if aux_count == 0 || versions.len() + aux_count > MAX_VERSION_REQUIREMENTS {
            return unsupported("version auxiliary count exceeds the fixture limit or is empty");
        }
        let library = name_at(strings, u32_at(record, 4)? as u64, budget)?;
        if !needed.contains(&library) || !libraries.insert(library.clone()) {
            return invalid("version-need library is undeclared or repeated");
        }
        let aux_offset = u32_at(record, 8)? as u64;
        if aux_offset < 16 {
            return invalid("version auxiliary overlaps its parent");
        }
        let mut aux_address = add(address, aux_offset)?;
        for aux_index in 0..aux_count {
            let aux = image.table(aux_address, 16, 4)?;
            let flags = u16_at(aux, 4)?;
            let version_index = u16_at(aux, 6)?;
            if flags != 0 || !(2..0x8000).contains(&version_index) {
                return unsupported("weak/hidden or reserved version requirement");
            }
            if !indexes.insert(version_index) {
                return invalid("duplicate version requirement index");
            }
            let name = name_at(strings, u32_at(aux, 8)? as u64, budget)?;
            if name.is_empty() || u32_at(aux, 0)? != elf_hash(&name) {
                return invalid("version name/hash mismatch");
            }
            versions.push(VersionRequirement {
                library: library.clone(),
                name,
                index: version_index,
                flags,
            });
            let next = u32_at(aux, 12)? as u64;
            if aux_index + 1 == aux_count {
                if next != 0 {
                    return invalid("version auxiliary chain exceeds declared count");
                }
            } else {
                if next < 16 {
                    return invalid("version auxiliary chain is truncated/overlapping");
                }
                aux_address = add(aux_address, next)?;
            }
        }
        let next = u32_at(record, 12)? as u64;
        if index + 1 == count {
            if next != 0 {
                return invalid("version-need chain exceeds declared count");
            }
        } else {
            if next < 16 {
                return invalid("version-need chain is truncated/overlapping");
            }
            address = add(address, next)?;
        }
    }
    Ok(versions)
}

fn parse_relocations(
    image: &mut Image<'_>,
    address: u64,
    size: u64,
    table: RelocationTable,
    symbols: &[DynamicSymbol],
    output: &mut Vec<Relocation>,
) -> Result<()> {
    if size % 24 != 0 || size / 24 > (MAX_RELOCATIONS - output.len()) as u64 {
        return unsupported("invalid or excessive RELA table count");
    }
    let entries = image.table(address, size, 8)?;
    for entry in entries.chunks_exact(24) {
        let offset = u64_at(entry, 0)?;
        let info = u64_at(entry, 8)?;
        let kind = info as u32;
        let symbol_index = (info >> 32) as usize;
        let addend = i64::from_le_bytes(entry[16..24].try_into().unwrap());
        if !matches!(kind, 1025..=1027) {
            return unsupported(format!(
                "AArch64 relocation type {kind} (ABS64/TLS/IFUNC/copy/other extensions are not admitted)"
            ));
        }
        if (table == RelocationTable::Plt) != (kind == 1026) {
            return invalid("PLT/ordinary relocation-kind mismatch");
        }
        if offset % 8 != 0 || !image.writable(offset, 8) {
            return unsupported("relocation target outside aligned writable non-executable memory");
        }
        if kind == 1027 {
            if symbol_index != 0
                || addend < 0
                || !image
                    .loads
                    .iter()
                    .any(|load| contains(load, addend as u64, 1))
            {
                return invalid("invalid RELATIVE symbol/addend");
            }
        } else {
            let symbol = symbols.get(symbol_index).ok_or_else(|| {
                ElfError::Invalid("relocation symbol index outside DT_HASH count".into())
            })?;
            if symbol_index == 0 || symbol.binding == SymbolBinding::Local {
                return invalid("named relocation references null/local symbol");
            }
            if addend != 0 {
                return unsupported("nonzero named-relocation addend");
            }
            if kind == 1026 && symbol.kind == SymbolKind::Object {
                return invalid("PLT relocation references an object");
            }
        }
        output.push(Relocation {
            offset,
            kind,
            symbol_index,
            addend,
            table,
        });
    }
    Ok(())
}

fn check_initializer_array(
    image: &Image<'_>,
    tags: &BTreeMap<u64, u64>,
    pointer: u64,
    size_tag: u64,
    relocations: &[Relocation],
) -> Result<()> {
    let Some((address, size)) = paired(tags, pointer, size_tag)? else {
        return Ok(());
    };
    if address % 8 != 0 || size % 8 != 0 || size > 4096 * 8 || !image.writable(address, size) {
        return invalid("initializer array has invalid bounds/alignment/permissions");
    }
    let bytes = image.read(address, size)?;
    let file_offset = image.file_offset(address, size)?;
    let end = add(file_offset, size)?;
    if image
        .metadata
        .iter()
        .any(|&(start, limit)| file_offset < limit && start < end)
    {
        return invalid("initializer array overlaps loader/dynamic metadata");
    }
    let by_target: BTreeMap<_, _> = relocations
        .iter()
        .map(|relocation| (relocation.offset, relocation))
        .collect();
    for (index, entry) in bytes.chunks_exact(8).enumerate() {
        let slot = add(address, (index * 8) as u64)?;
        let target = match by_target.get(&slot) {
            Some(relocation) if relocation.kind == 1027 => relocation.addend as u64,
            Some(_) => return unsupported("initializer array must use local RELATIVE relocations"),
            None => {
                if u64::from_le_bytes(entry.try_into().unwrap()) == 0 {
                    continue;
                }
                return invalid("nonzero initializer pointer lacks a RELATIVE relocation");
            }
        };
        if target % 4 != 0 || !image.executable(target) {
            return invalid("initializer array target outside executable memory");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const SONAME: &str = "libfixture.so";
    const DYNAMIC_FILE: usize = 0x1100;
    const STRINGS: usize = 0x300;
    const HASH: usize = 0x400;
    const SYMBOLS: usize = 0x500;
    const VERSYM: usize = 0x580;
    const VERNEED: usize = 0x600;
    const RELA: usize = 0x700;
    const PLT: usize = 0x730;
    const ARRAY_VM: u64 = 0x10400;
    const DATA_VM: u64 = 0x10500;

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) struct Fixture {
        pub(crate) bytes: Vec<u8>,
        pub(crate) tags: BTreeMap<u64, usize>,
        pub(crate) names: BTreeMap<&'static str, u32>,
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            let mut bytes = vec![0; 0x2000];
            bytes[..9].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00");
            put16(&mut bytes, 16, 3);
            put16(&mut bytes, 18, 183);
            put32(&mut bytes, 20, 1);
            put64(&mut bytes, 32, 64);
            put16(&mut bytes, 52, 64);
            put16(&mut bytes, 54, 56);
            put16(&mut bytes, 56, 5);
            // Two discontiguous virtual ranges exercise VM-to-file translation.
            let headers = [
                (PT_LOAD, 5, 0, 0, 0x1000, 0x1000, 4096),
                (PT_LOAD, 6, 0x1000, 0x10000, 0x1000, 0x1100, 4096),
                (PT_DYNAMIC, 6, DYNAMIC_FILE as u64, 0x10100, 0x200, 0x200, 8),
                (PT_GNU_STACK, 6, 0, 0, 0, 0, 16),
                (4, 4, 0x200, 0x200, 20, 20, 4),
            ];
            for (index, (kind, flags, file, address, size, memory, alignment)) in
                headers.into_iter().enumerate()
            {
                let offset = 64 + index * 56;
                put32(&mut bytes, offset, kind);
                put32(&mut bytes, offset + 4, flags);
                put64(&mut bytes, offset + 8, file);
                put64(&mut bytes, offset + 16, address);
                put64(&mut bytes, offset + 24, address);
                put64(&mut bytes, offset + 32, size);
                put64(&mut bytes, offset + 40, memory);
                put64(&mut bytes, offset + 48, alignment);
            }
            put32(&mut bytes, 0x200, 4);
            put32(&mut bytes, 0x204, 4);
            put32(&mut bytes, 0x208, 3);
            bytes[0x20c..0x210].copy_from_slice(b"GNU\0");
            bytes[0x210..0x214].copy_from_slice(&[1, 2, 3, 4]);
            let mut names = BTreeMap::new();
            let mut strings = vec![0];
            for name in [
                SONAME,
                "libc.so.6",
                "luaopen_fixture",
                "data",
                "getpid",
                "GLIBC_2.17",
                "_ITM_registerTMCloneTable",
                "other.so",
                "helper",
                "luaL_error",
                "lua_newstate",
                "luaL_newstate",
                "lua_close",
            ] {
                names.insert(name, strings.len() as u32);
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
            }
            bytes[STRINGS..STRINGS + strings.len()].copy_from_slice(&strings);
            put32(&mut bytes, HASH, 1);
            put32(&mut bytes, HASH + 4, 4);
            put32(&mut bytes, HASH + 8, 1);
            for (index, next) in [0, 2, 3, 0].into_iter().enumerate() {
                put32(&mut bytes, HASH + 12 + index * 4, next);
            }
            let symbols = [
                (0, 0, 0, 0, 0),
                (names["luaopen_fixture"], 0x12, 1, 0x800, 16),
                (names["data"], 0x11, 2, DATA_VM, 4),
                (names["getpid"], 0x12, 0, 0, 0),
            ];
            for (index, (name, info, section, value, size)) in symbols.into_iter().enumerate() {
                let offset = SYMBOLS + index * 24;
                put32(&mut bytes, offset, name);
                bytes[offset + 4] = info;
                put16(&mut bytes, offset + 6, section);
                put64(&mut bytes, offset + 8, value);
                put64(&mut bytes, offset + 16, size);
            }
            for (index, version) in [0, 1, 1, 2].into_iter().enumerate() {
                put16(&mut bytes, VERSYM + index * 2, version);
            }
            put16(&mut bytes, VERNEED, 1);
            put16(&mut bytes, VERNEED + 2, 1);
            put32(&mut bytes, VERNEED + 4, names["libc.so.6"]);
            put32(&mut bytes, VERNEED + 8, 16);
            put32(&mut bytes, VERNEED + 16, elf_hash("GLIBC_2.17"));
            put16(&mut bytes, VERNEED + 22, 2);
            put32(&mut bytes, VERNEED + 24, names["GLIBC_2.17"]);
            for (offset, target, kind, symbol, addend) in [
                (RELA, ARRAY_VM, 1027, 0, 0x800),
                (RELA + 24, DATA_VM + 16, 1025, 2, 0),
                (PLT, DATA_VM + 24, 1026, 3, 0),
            ] {
                put64(&mut bytes, offset, target);
                put64(&mut bytes, offset + 8, ((symbol as u64) << 32) | kind);
                put64(&mut bytes, offset + 16, addend);
            }
            let entries = [
                (DT_NEEDED, names["libc.so.6"] as u64),
                (DT_SONAME, names[SONAME] as u64),
                (DT_HASH, HASH as u64),
                (DT_STRTAB, STRINGS as u64),
                (DT_STRSZ, strings.len() as u64),
                (DT_SYMTAB, SYMBOLS as u64),
                (DT_SYMENT, 24),
                (DT_INIT_ARRAY, ARRAY_VM),
                (DT_INIT_ARRAYSZ, 8),
                (DT_RELA, RELA as u64),
                (DT_RELASZ, 48),
                (DT_RELAENT, 24),
                (DT_RELACOUNT, 1),
                (DT_JMPREL, PLT as u64),
                (DT_PLTRELSZ, 24),
                (DT_PLTREL, DT_RELA),
                (DT_PLTGOT, ARRAY_VM + 16),
                (DT_FLAGS, 8),
                (DT_FLAGS_1, 1),
                (DT_VERSYM, VERSYM as u64),
                (DT_VERNEED, VERNEED as u64),
                (DT_VERNEEDNUM, 1),
            ];
            let mut tags = BTreeMap::new();
            for (index, (tag, value)) in entries.into_iter().enumerate() {
                let offset = DYNAMIC_FILE + index * 16;
                tags.insert(tag, offset);
                put64(&mut bytes, offset, tag);
                put64(&mut bytes, offset + 8, value);
            }
            Self { bytes, tags, names }
        }

        pub(crate) fn set(&mut self, tag: u64, value: u64) {
            put64(&mut self.bytes, self.tags[&tag] + 8, value);
        }

        pub(crate) fn replace(&mut self, tag: u64, replacement: u64) {
            put64(&mut self.bytes, self.tags[&tag], replacement);
        }

        pub(crate) fn symbol_mut(&mut self, index: usize) -> &mut [u8] {
            &mut self.bytes[SYMBOLS + index * 24..SYMBOLS + (index + 1) * 24]
        }

        pub(crate) fn rename_symbol(&mut self, index: usize, name: &'static str) {
            let offset = self.names[name];
            put32(self.symbol_mut(index), 0, offset);
        }

        pub(crate) fn set_version(&mut self, index: usize, version: u16) {
            put16(&mut self.bytes, VERSYM + index * 2, version);
        }

        fn inspect(&self) -> Result<ElfFacts> {
            inspect(&self.bytes, SONAME, &BTreeSet::from(["getpid".into()]))
        }
    }

    fn rejected(fixture: &Fixture, text: &str) {
        let error = fixture.inspect().unwrap_err();
        assert!(
            error.to_string().contains(text),
            "expected {text:?}, received {error}"
        );
    }

    #[test]
    fn extracts_indexed_symbols_relocations_versions_and_constructor_facts() {
        let facts = Fixture::new().inspect().unwrap();
        assert_eq!(facts.soname, SONAME);
        assert_eq!(facts.needed, ["libc.so.6"]);
        assert!(facts.has_constructors);
        assert_eq!(facts.symbols.len(), 4);
        let function = facts.symbol("luaopen_fixture").unwrap();
        assert!(function.defined);
        assert_eq!(
            (function.kind, function.value, function.size),
            (SymbolKind::Function, 0x800, 16)
        );
        assert!(facts.contains_executable_address(function.value));
        assert!(!facts.contains_executable_address(DATA_VM));
        assert_eq!(facts.symbol("data").unwrap().kind, SymbolKind::Object);
        let import = facts.symbol("getpid").unwrap();
        assert!(!import.defined);
        assert_eq!(import.version_index, 2);
        assert_eq!(
            facts.version_requirements,
            [VersionRequirement {
                library: "libc.so.6".into(),
                name: "GLIBC_2.17".into(),
                index: 2,
                flags: 0
            }]
        );
        assert_eq!(
            facts
                .relocations
                .iter()
                .map(|item| (
                    item.kind,
                    item.offset,
                    item.symbol_index,
                    item.addend,
                    item.table
                ))
                .collect::<Vec<_>>(),
            [
                (1027, ARRAY_VM, 0, 0x800, RelocationTable::Rela),
                (1025, DATA_VM + 16, 2, 0, RelocationTable::Rela),
                (1026, DATA_VM + 24, 3, 0, RelocationTable::Plt),
            ]
        );
    }

    #[test]
    fn section_headers_do_not_determine_admission() {
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, 40, u64::MAX);
        put16(&mut fixture.bytes, 58, u16::MAX);
        put16(&mut fixture.bytes, 60, u16::MAX);
        put16(&mut fixture.bytes, 62, u16::MAX);
        fixture.inspect().unwrap();
    }

    #[test]
    fn rejects_truncated_headers_and_program_ranges() {
        for length in [0, 4, 63, 64, 200] {
            let fixture = Fixture::new();
            assert!(inspect(&fixture.bytes[..length], SONAME, &BTreeSet::new()).is_err());
        }
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, 32, u64::MAX - 7);
        rejected(&fixture, "overflow");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, 64 + 56 + 8, u64::MAX);
        rejected(&fixture, "overflow");
    }

    #[test]
    fn every_file_prefix_is_rejected_without_panicking() {
        let fixture = Fixture::new();
        let imports = BTreeSet::from(["getpid".into()]);
        for length in 0..fixture.bytes.len() {
            assert!(
                inspect(&fixture.bytes[..length], SONAME, &imports).is_err(),
                "accepted truncated prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_other_machine_class_endian_and_executable() {
        for (offset, value) in [(4, 1), (5, 2), (7, 9)] {
            let mut fixture = Fixture::new();
            fixture.bytes[offset] = value;
            rejected(&fixture, "ELF64");
        }
        for (offset, value) in [(16, 2), (18, 62)] {
            let mut fixture = Fixture::new();
            put16(&mut fixture.bytes, offset, value);
            rejected(&fixture, "ET_DYN AArch64");
        }
    }

    #[test]
    fn rejects_duplicate_dynamic_and_missing_stack_segments() {
        let mut fixture = Fixture::new();
        let dynamic = fixture.bytes[64 + 112..64 + 168].to_vec();
        fixture.bytes[64 + 224..64 + 280].copy_from_slice(&dynamic);
        rejected(&fixture, "multiple PT_DYNAMIC");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, 64 + 168, 7);
        rejected(&fixture, "program-header type");
    }

    #[test]
    fn rejects_writable_code_executable_stack_tls_and_architecture_properties() {
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, 64 + 4, 7);
        rejected(&fixture, "writable executable");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, 64 + 168 + 4, 7);
        rejected(&fixture, "writable executable");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, 64 + 224, 7);
        rejected(&fixture, "program-header type");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, 0x208, 5);
        rejected(&fixture, "GNU build-id");
    }

    #[test]
    fn rejects_load_aliases_unbacked_addresses_and_bad_dynamic_mapping() {
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, 64 + 56 + 16, 0);
        rejected(&fixture, "overlapping load virtual");
        let mut fixture = Fixture::new();
        fixture.set(DT_STRTAB, 0x11000); // BSS exists, but has no file bytes.
        rejected(&fixture, "file-backed");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, 64 + 112 + 16, 0x10108);
        rejected(&fixture, "PT_DYNAMIC does not match");
    }

    #[test]
    fn rejects_unknown_search_path_textrel_filter_audit_and_rel_metadata() {
        for tag in [
            15,
            29,
            22,
            17,
            18,
            19,
            35,
            36,
            37,
            0x7fff_ffff,
            0x7fff_fffd,
            0x6fff_fefc,
            0x6fff_fefb,
            0x6fff_fef5,
            0x6fff_fffc,
        ] {
            let mut fixture = Fixture::new();
            fixture.replace(DT_FLAGS_1, tag);
            rejected(&fixture, "dynamic tag");
        }
    }

    #[test]
    fn rejects_duplicate_unterminated_and_hidden_dynamic_entries() {
        let mut fixture = Fixture::new();
        fixture.replace(DT_FLAGS_1, DT_FLAGS);
        rejected(&fixture, "duplicate dynamic tag");
        let mut fixture = Fixture::new();
        for index in 22..32 {
            put64(&mut fixture.bytes, DYNAMIC_FILE + index * 16, DT_NEEDED);
        }
        rejected(&fixture, "unterminated PT_DYNAMIC");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, DYNAMIC_FILE + 23 * 16, DT_NEEDED);
        rejected(&fixture, "after DT_NULL");
    }

    #[test]
    fn requires_immediate_binding_and_rejects_other_flags() {
        let mut fixture = Fixture::new();
        fixture.set(DT_FLAGS, 0);
        fixture.set(DT_FLAGS_1, 0);
        rejected(&fixture, "immediate binding is required");
        for (tag, value) in [
            (DT_FLAGS, 4),
            (DT_FLAGS, 16),
            (DT_FLAGS_1, 8),
            (DT_FLAGS_1, 0x8000000),
        ] {
            let mut fixture = Fixture::new();
            fixture.set(tag, value);
            rejected(&fixture, "dynamic flags");
        }
    }

    #[test]
    fn validates_soname_needed_and_string_bounds() {
        let fixture = Fixture::new();
        assert!(
            matches!(inspect(&fixture.bytes, "wrong.so", &BTreeSet::new()), Err(ElfError::Invalid(message)) if message.contains("SONAME"))
        );
        let mut fixture = Fixture::new();
        let name = fixture.names["libc.so.6"] as usize;
        fixture.bytes[STRINGS + name] = b'/';
        rejected(&fixture, "basenames");
        let mut fixture = Fixture::new();
        fixture.set(DT_SONAME, 10_000);
        rejected(&fixture, "string offset");
        let mut fixture = Fixture::new();
        let size = u64_at(&fixture.bytes, (fixture.tags[&DT_STRSZ] + 8) as u64).unwrap();
        fixture.bytes[STRINGS + size as usize - 1] = b'x';
        rejected(&fixture, "string-table boundary");
    }

    #[test]
    fn bounds_sysv_hash_counts_indexes_and_cycles() {
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, HASH + 4, (MAX_SYMBOLS + 1) as u32);
        rejected(&fixture, "SysV hash count");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, HASH + 8, 4);
        rejected(&fixture, "SysV hash index");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, HASH + 12 + 3 * 4, 1);
        rejected(&fixture, "cycle");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, HASH + 8, 0);
        rejected(&fixture, "exported symbol missing");
    }

    #[test]
    fn permits_only_canonical_local_section_markers() {
        let mut fixture = Fixture::new();
        let index = SYMBOLS + 2 * 24;
        put32(&mut fixture.bytes, index, 0);
        fixture.bytes[index + 4] = 3;
        put64(&mut fixture.bytes, index + 16, 0);
        put16(&mut fixture.bytes, VERSYM + 2 * 2, 0);
        // Ordinary data relocation cannot reference a local section marker.
        put64(&mut fixture.bytes, RELA + 24 + 8, (1u64 << 32) | 1025);
        fixture.inspect().unwrap();
        fixture.bytes[index + 4] = 0x13;
        rejected(&fixture, "section symbol");
    }

    #[test]
    fn rejects_tls_ifunc_unique_and_undeclared_undefined_symbols() {
        for info in [0x16, 0x1a, 0xa2] {
            let mut fixture = Fixture::new();
            fixture.bytes[SYMBOLS + 24 + 4] = info;
            rejected(&fixture, "symbol");
        }
        let fixture = Fixture::new();
        assert!(
            matches!(inspect(&fixture.bytes, SONAME, &BTreeSet::new()), Err(ElfError::Invalid(message)) if message.contains("undeclared undefined symbol"))
        );
    }

    #[test]
    fn compiler_hooks_require_exact_weak_unversioned_notype_identity() {
        let mut fixture = Fixture::new();
        put32(
            &mut fixture.bytes,
            SYMBOLS + 72,
            fixture.names["_ITM_registerTMCloneTable"],
        );
        fixture.bytes[SYMBOLS + 72 + 4] = 0x20;
        put16(&mut fixture.bytes, VERSYM + 6, 1);
        inspect(&fixture.bytes, SONAME, &BTreeSet::new()).unwrap();
        fixture.bytes[SYMBOLS + 72 + 4] = 0x10;
        assert!(
            matches!(inspect(&fixture.bytes, SONAME, &BTreeSet::new()), Err(ElfError::Invalid(message)) if message.contains("undeclared undefined symbol"))
        );
    }

    #[test]
    fn rejects_bad_symbol_extents_and_reserved_indexes() {
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, SYMBOLS + 24 + 8, 0x801);
        rejected(&fixture, "4-byte aligned");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, SYMBOLS + 24 + 8, DATA_VM);
        rejected(&fixture, "function symbol");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, SYMBOLS + 24 + 16, u64::MAX);
        rejected(&fixture, "defined symbol");
        let mut fixture = Fixture::new();
        put16(&mut fixture.bytes, SYMBOLS + 24 + 6, 0xfff1);
        rejected(&fixture, "reserved");
    }

    #[test]
    fn rejects_inconsistent_table_tags_sizes_and_overlaps() {
        for (tag, value, diagnostic) in [
            (DT_SYMENT, 16, "DT_SYMENT"),
            (DT_RELAENT, 16, "DT_RELAENT"),
            (DT_PLTREL, 17, "RELA"),
            (DT_RELASZ, 47, "RELA"),
            (DT_RELACOUNT, 3, "RELACOUNT"),
            (DT_SYMTAB, STRINGS as u64, "overlapping"),
        ] {
            let mut fixture = Fixture::new();
            fixture.set(tag, value);
            rejected(&fixture, diagnostic);
        }
        let mut fixture = Fixture::new();
        fixture.replace(DT_INIT_ARRAYSZ, DT_INIT);
        fixture.set(DT_INIT_ARRAYSZ, 0x800);
        rejected(&fixture, "inconsistent dynamic");
    }

    #[test]
    fn rejects_unsupported_relocations_bad_indexes_and_executable_targets() {
        for kind in [257, 1024, 1028, 1031, 1032, 1041] {
            let mut fixture = Fixture::new();
            put64(&mut fixture.bytes, RELA + 24 + 8, (2u64 << 32) | kind);
            rejected(&fixture, "relocation type");
        }
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, PLT + 8, (4u64 << 32) | 1026);
        rejected(&fixture, "symbol index");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, RELA + 24, 0x800);
        rejected(&fixture, "writable non-executable");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, PLT, DATA_VM + 16);
        rejected(&fixture, "duplicate relocation target");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, RELA + 24, 0x10100);
        rejected(&fixture, "inspection metadata");
    }

    #[test]
    fn validates_version_hash_library_index_and_chain_termination() {
        for (offset, value, diagnostic) in [
            (VERNEED + 16, 0, "hash mismatch"),
            (
                VERNEED + 4,
                Fixture::new().names["other.so"],
                "library is undeclared",
            ),
            (VERNEED + 12, 16, "chain exceeds"),
            (VERNEED + 28, 16, "chain exceeds"),
        ] {
            let mut fixture = Fixture::new();
            put32(&mut fixture.bytes, offset, value);
            rejected(&fixture, diagnostic);
        }
        let mut fixture = Fixture::new();
        put16(&mut fixture.bytes, VERSYM + 6, 3);
        rejected(&fixture, "symbol-version index");
        let mut fixture = Fixture::new();
        put32(&mut fixture.bytes, VERNEED + 8, 0);
        rejected(&fixture, "overlaps its parent");
        let mut fixture = Fixture::new();
        fixture.set(DT_VERNEEDNUM, 2);
        rejected(&fixture, "truncated/overlapping");
    }

    #[test]
    fn initializer_arrays_require_local_executable_relative_targets() {
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, RELA + 16, DATA_VM);
        rejected(&fixture, "initializer array target");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, RELA, DATA_VM + 32);
        put64(&mut fixture.bytes, 0x1400, 0x800);
        rejected(&fixture, "lacks a RELATIVE relocation");
        let mut fixture = Fixture::new();
        fixture.set(DT_INIT_ARRAYSZ, 9);
        rejected(&fixture, "initializer array has invalid");
        let mut fixture = Fixture::new();
        fixture.set(DT_INIT_ARRAY, ARRAY_VM + 16);
        rejected(&fixture, "initializer array overlaps");
        let mut fixture = Fixture::new();
        put64(&mut fixture.bytes, RELA + 24, ARRAY_VM + 16);
        rejected(&fixture, "inspection metadata");
    }
}
