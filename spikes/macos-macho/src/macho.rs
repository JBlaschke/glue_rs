//! Bounded classic-fixup Mach-O preflight for the controlled A1 fixture.
//!
//! This is deliberately smaller than dyld: plain arm64 C dylibs only, with
//! eager eight-byte pointer fixups. A code-signature command is retained as
//! opaque metadata; parsing it does not authenticate a signature.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

pub const PAGE_SIZE: u64 = 16 * 1024;
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_VM_SIZE: u64 = 32 * 1024 * 1024;
const MAX_FIXUPS: usize = 4096;
const MAX_SYMBOLS: usize = 4096;
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_NAME: usize = 256;

#[derive(Clone, Debug)]
pub struct Image {
    pub segments: Vec<Segment>,
    pub vm_size: u64,
    pub minimum_os_version: u32,
    pub install_name: String,
    pub dependencies: Vec<String>,
    pub rebases: Vec<u64>,
    pub binds: Vec<Bind>,
    pub exports: BTreeMap<String, u64>,
    pub constructors: Vec<u64>,
    pub code_signature: Option<Range<usize>>,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub initial_protection: u32,
    pub maximum_protection: u32,
    pub read_only_after_fixups: bool,
    sections: Vec<Section>,
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    address: u64,
    size: u64,
    flags: u32,
    indirect_start: u32,
    stub_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bind {
    pub offset: u64,
    pub library_ordinal: u8,
    pub symbol: String,
    pub addend: i64,
}

impl Image {
    pub fn segment_containing(&self, offset: u64, length: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .find(|segment| contains(segment.vm_address, segment.vm_size, offset, length))
    }

    pub fn is_executable(&self, offset: u64) -> bool {
        offset % 4 == 0
            && self.segments.iter().any(|segment| {
                segment.initial_protection & 4 != 0
                    && segment.sections.iter().any(|section| {
                        section.name == "__text"
                            && contains(section.address, section.size, offset, 4)
                    })
            })
    }

    fn has_section_address(&self, offset: u64, length: u64) -> bool {
        self.segments
            .iter()
            .flat_map(|segment| &segment.sections)
            .any(|section| contains(section.address, section.size, offset, length))
    }

    fn pointer_file_offset(&self, offset: u64) -> Result<usize, String> {
        let segment = self
            .segment_containing(offset, 8)
            .ok_or("pointer outside mapped segment")?;
        let relative = offset
            .checked_sub(segment.vm_address)
            .ok_or("pointer underflow")?;
        if relative.checked_add(8).ok_or("pointer overflow")? > segment.file_size {
            return Err("fixup pointer is not backed by image bytes".into());
        }
        usize::try_from(
            segment
                .file_offset
                .checked_add(relative)
                .ok_or("file pointer overflow")?,
        )
        .map_err(|_| "file pointer overflow".into())
    }
}

#[derive(Clone, Copy)]
struct DyldInfo {
    rebase: (u32, u32),
    bind: (u32, u32),
    export: (u32, u32),
}

#[derive(Clone, Copy)]
struct Symtab {
    symbols: u32,
    count: u32,
    strings: u32,
    string_size: u32,
}

#[derive(Clone, Copy)]
struct Dysymtab {
    local_start: u32,
    local_count: u32,
    external_start: u32,
    external_count: u32,
    undefined_start: u32,
    undefined_count: u32,
    indirect: u32,
    indirect_count: u32,
}

/// Validate the complete supported metadata before allocating executable memory.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if bytes.len() < 32 || bytes.len() > MAX_IMAGE_BYTES {
        return Err("Mach-O image must be between 32 bytes and 16 MiB".into());
    }
    if u32_at(bytes, 0)? != 0xfeed_facf
        || u32_at(bytes, 4)? != 0x0100_000c
        || u32_at(bytes, 8)? != 0
        || u32_at(bytes, 12)? != 6
    {
        return Err("only little-endian arm64 MH_DYLIB images are supported".into());
    }
    let flags = u32_at(bytes, 24)?;
    let allowed_flags = 0x1 | 0x4 | 0x8 | 0x80 | 0x2000 | 0x10_0000 | 0x0200_0000;
    if flags & (0x4 | 0x80) != 0x84 || flags & !allowed_flags != 0 || u32_at(bytes, 28)? != 0 {
        return Err("unsupported Mach-O header flags or reserved field".into());
    }
    let command_count = u32_at(bytes, 16)? as usize;
    let command_bytes = u32_at(bytes, 20)? as usize;
    if command_count == 0 || command_count > 64 || command_bytes > 64 * 1024 {
        return Err("load-command count or bytes exceed the controlled limit".into());
    }
    let commands = range(bytes, 32, command_bytes)?;
    let command_end = commands.end;
    let mut position = commands.start;
    let mut segments = Vec::new();
    let mut dependencies = Vec::new();
    let mut install_name = None;
    let mut dyld = None;
    let mut symtab = None;
    let mut dysymtab = None;
    let mut code_signature = None;
    let mut function_starts = None;
    let mut data_in_code = None;
    let mut metadata_ranges = Vec::new();
    let mut unique_commands = BTreeSet::new();
    let mut build_version = false;
    let mut minimum_os_version = 0;

    for _ in 0..command_count {
        if position.checked_add(8).ok_or("command overflow")? > command_end {
            return Err("truncated Mach-O load command".into());
        }
        let kind = u32_at(bytes, position)?;
        let size = u32_at(bytes, position + 4)? as usize;
        if size < 8
            || size % 8 != 0
            || position.checked_add(size).ok_or("command overflow")? > command_end
        {
            return Err("invalid Mach-O load-command size".into());
        }
        let command = &bytes[position..position + size];
        if kind != 0x19 && kind != 0xc && !unique_commands.insert(kind) {
            return Err("duplicate Mach-O singleton load command".into());
        }
        match kind {
            0x19 => segments.push(parse_segment(command, bytes.len())?),
            0xc | 0xd => {
                let name = parse_dylib(command)?;
                if kind == 0xd {
                    install_name = Some(name);
                } else {
                    if dependencies.len() >= 8 || dependencies.contains(&name) {
                        return Err("too many or duplicate dylib dependencies".into());
                    }
                    dependencies.push(name);
                }
            }
            0x8000_0022 => {
                exact_size(command, 48)?;
                if u32_at(command, 24)? != 0
                    || u32_at(command, 28)? != 0
                    || u32_at(command, 32)? != 0
                    || u32_at(command, 36)? != 0
                {
                    return Err("weak and lazy binding streams are unsupported".into());
                }
                let info = DyldInfo {
                    rebase: (u32_at(command, 8)?, u32_at(command, 12)?),
                    bind: (u32_at(command, 16)?, u32_at(command, 20)?),
                    export: (u32_at(command, 40)?, u32_at(command, 44)?),
                };
                for (offset, length) in [info.rebase, info.bind, info.export] {
                    add_metadata_range(bytes, offset, length, &mut metadata_ranges)?;
                }
                dyld = Some(info);
            }
            0x2 => {
                exact_size(command, 24)?;
                let table = Symtab {
                    symbols: u32_at(command, 8)?,
                    count: u32_at(command, 12)?,
                    strings: u32_at(command, 16)?,
                    string_size: u32_at(command, 20)?,
                };
                if table.count as usize > MAX_SYMBOLS {
                    return Err("symbol count exceeds the controlled limit".into());
                }
                add_metadata_range(
                    bytes,
                    table.symbols,
                    table.count.checked_mul(16).ok_or("symbol table overflow")?,
                    &mut metadata_ranges,
                )?;
                add_metadata_range(
                    bytes,
                    table.strings,
                    table.string_size,
                    &mut metadata_ranges,
                )?;
                symtab = Some(table);
            }
            0xb => {
                exact_size(command, 80)?;
                // No old module tables, external references, or relocation tables.
                for offset in [32, 36, 40, 44, 48, 52, 64, 68, 72, 76] {
                    if u32_at(command, offset)? != 0 {
                        return Err("unsupported legacy dynamic-symbol table metadata".into());
                    }
                }
                let table = Dysymtab {
                    local_start: u32_at(command, 8)?,
                    local_count: u32_at(command, 12)?,
                    external_start: u32_at(command, 16)?,
                    external_count: u32_at(command, 20)?,
                    undefined_start: u32_at(command, 24)?,
                    undefined_count: u32_at(command, 28)?,
                    indirect: u32_at(command, 56)?,
                    indirect_count: u32_at(command, 60)?,
                };
                if table.indirect_count as usize > MAX_SYMBOLS {
                    return Err("indirect symbol count exceeds the controlled limit".into());
                }
                add_metadata_range(
                    bytes,
                    table.indirect,
                    table
                        .indirect_count
                        .checked_mul(4)
                        .ok_or("indirect symbol table overflow")?,
                    &mut metadata_ranges,
                )?;
                dysymtab = Some(table);
            }
            0x1b => exact_size(command, 24)?, // UUID is inert metadata.
            0x32 => {
                if size < 24
                    || u32_at(command, 8)? != 1
                    || u32_at(command, 20)? > 8
                    || size != 24 + u32_at(command, 20)? as usize * 8
                {
                    return Err("only bounded macOS build-version metadata is supported".into());
                }
                let minimum = u32_at(command, 12)?;
                let sdk = u32_at(command, 16)?;
                if minimum >> 16 < 11 || minimum > sdk {
                    return Err("invalid macOS minimum/SDK version".into());
                }
                for offset in (24..size).step_by(8) {
                    if !(1..=3).contains(&u32_at(command, offset)?) {
                        return Err("unknown build tool in build-version metadata".into());
                    }
                }
                build_version = true;
                minimum_os_version = minimum;
            }
            0x2a => {
                exact_size(command, 16)?;
                if u64_at(command, 8)? != 0 {
                    return Err("nonzero source-version metadata is unsupported".into());
                }
            }
            0x1d | 0x26 | 0x29 => {
                exact_size(command, 16)?;
                let offset = u32_at(command, 8)?;
                let length = u32_at(command, 12)?;
                let payload = add_metadata_range(bytes, offset, length, &mut metadata_ranges)?;
                match kind {
                    0x1d => {
                        if payload.is_empty() {
                            return Err("empty code-signature metadata".into());
                        }
                        code_signature = Some(payload);
                    }
                    0x26 => function_starts = Some(payload),
                    _ => data_in_code = Some(payload),
                }
            }
            _ => return Err(format!("unsupported Mach-O load command {kind:#x}")),
        }
        position += size;
    }
    if position != command_end || !build_version || segments.len() < 2 || segments.len() > 4 {
        return Err("incomplete or oversized controlled Mach-O layout".into());
    }
    let info = dyld.ok_or("classic LC_DYLD_INFO_ONLY fixups are required")?;
    let symtab = symtab.ok_or("LC_SYMTAB is required")?;
    let dysymtab = dysymtab.ok_or("LC_DYSYMTAB is required")?;
    let install_name = install_name.ok_or("LC_ID_DYLIB is required")?;
    let code_signature = code_signature.ok_or("LC_CODE_SIGNATURE metadata is required")?;
    let mut next_vm = 0;
    let mut previous_file_end = 0;
    let mut names = BTreeSet::new();
    for (index, segment) in segments.iter().enumerate() {
        if !names.insert(&segment.name)
            || segment.vm_address != next_vm
            || segment.file_offset < previous_file_end
        {
            return Err("overlapping, unordered, or discontinuous Mach-O segments".into());
        }
        if index == 0
            && (segment.name != "__TEXT"
                || segment.file_offset != 0
                || segment.file_size < command_end as u64)
        {
            return Err("Mach-O headers must reside in the first __TEXT segment".into());
        }
        next_vm = segment
            .vm_address
            .checked_add(segment.vm_size)
            .ok_or("VM size overflow")?;
        previous_file_end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or("file size overflow")?;
    }
    if next_vm > MAX_VM_SIZE
        || segments
            .last()
            .is_none_or(|segment| segment.name != "__LINKEDIT")
    {
        return Err("invalid or oversized Mach-O VM range".into());
    }
    let linkedit = segments.last().ok_or("missing __LINKEDIT")?;
    if previous_file_end != bytes.len() as u64 || code_signature.end != bytes.len() {
        return Err("trailing or unaffiliated Mach-O bytes are unsupported".into());
    }
    for payload in &metadata_ranges {
        if !contains(
            linkedit.file_offset,
            linkedit.file_size,
            payload.start as u64,
            payload.len() as u64,
        ) {
            return Err("Mach-O metadata must reside in __LINKEDIT".into());
        }
    }
    let mut image = Image {
        segments,
        vm_size: next_vm,
        minimum_os_version,
        install_name,
        dependencies,
        rebases: Vec::new(),
        binds: Vec::new(),
        exports: BTreeMap::new(),
        constructors: Vec::new(),
        code_signature: Some(code_signature),
    };
    for segment in &image.segments {
        for section in &segment.sections {
            if segment.name == "__TEXT" && section.address < command_end as u64 {
                return Err("__TEXT sections overlap Mach-O headers or load commands".into());
            }
            if section.flags & 0xff == 1 {
                let relative = section.address - segment.vm_address;
                let backed_size = section.size.min(segment.file_size.saturating_sub(relative));
                let offset = usize::try_from(segment.file_offset + relative)
                    .map_err(|_| "zero-fill offset overflow")?;
                if backed_size != 0
                    && bytes[range(bytes, offset, backed_size as usize)?]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err("zero-fill section has nonzero backing bytes".into());
                }
            }
            if section.name == "__mod_init_func" {
                for offset in (0..section.size).step_by(8) {
                    image.constructors.push(section.address + offset);
                }
            }
        }
    }
    if image.constructors.len() > 64 {
        return Err("too many constructor pointers".into());
    }
    image.rebases = parse_rebases(stream(bytes, info.rebase)?, &image)?;
    image.binds = parse_binds(stream(bytes, info.bind)?, &image)?;
    let mut writes = BTreeSet::new();
    for offset in image
        .rebases
        .iter()
        .chain(image.binds.iter().map(|bind| &bind.offset))
    {
        if !writes.insert(*offset) {
            return Err("duplicate or overlapping pointer fixups".into());
        }
    }
    for offset in &image.rebases {
        let target = u64_at(bytes, image.pointer_file_offset(*offset)?)?;
        if !image.has_section_address(target, 1) {
            return Err("rebased pointer target is outside supported image sections".into());
        }
    }
    for binding in &image.binds {
        if u64_at(bytes, image.pointer_file_offset(binding.offset)?)? != 0 {
            return Err("eager import slot must start as a null pointer".into());
        }
    }
    for offset in &image.constructors {
        if !image.rebases.contains(offset)
            || !image.is_executable(u64_at(bytes, image.pointer_file_offset(*offset)?)?)
        {
            return Err("constructor requires a rebased in-image __text pointer".into());
        }
    }
    image.exports = parse_exports(stream(bytes, info.export)?, &image)?;
    validate_symbols(bytes, symtab, dysymtab, &image)?;
    if let Some(payload) = function_starts {
        validate_function_starts(&bytes[payload], &image)?;
    }
    if let Some(payload) = data_in_code {
        validate_data_in_code(&bytes[payload], &image)?;
    }
    Ok(image)
}

fn parse_segment(command: &[u8], file_length: usize) -> Result<Segment, String> {
    if command.len() < 72 {
        return Err("truncated segment command".into());
    }
    let name = fixed_name(&command[8..24])?;
    let vm_address = u64_at(command, 24)?;
    let vm_size = u64_at(command, 32)?;
    let file_offset = u64_at(command, 40)?;
    let file_size = u64_at(command, 48)?;
    let maximum_protection = u32_at(command, 56)?;
    let initial_protection = u32_at(command, 60)?;
    let count = u32_at(command, 64)? as usize;
    let flags = u32_at(command, 68)?;
    let read_only_after_fixups = flags == 0x10;
    if count > 32
        || command.len() != 72 + count * 80
        || vm_size == 0
        || vm_address % PAGE_SIZE != 0
        || vm_size % PAGE_SIZE != 0
        || file_offset % PAGE_SIZE != 0
        || file_size > vm_size
        || file_offset
            .checked_add(file_size)
            .ok_or("segment file overflow")?
            > file_length as u64
        || maximum_protection != initial_protection
        || initial_protection & 1 == 0
        || initial_protection & 6 == 6
    {
        return Err("invalid segment range, alignment, or protection".into());
    }
    match name.as_str() {
        "__TEXT" if initial_protection == 5 && flags == 0 => {}
        "__DATA_CONST" if initial_protection == 3 && matches!(flags, 0 | 0x10) => {}
        "__DATA" if initial_protection == 3 && flags == 0 => {}
        "__LINKEDIT" if initial_protection == 1 && flags == 0 && count == 0 => {}
        _ => return Err("unsupported segment name, flags, or protection".into()),
    }
    if name != "__LINKEDIT" && file_size % PAGE_SIZE != 0 {
        return Err("non-linkedit segment file bytes must fill whole 16 KiB pages".into());
    }
    let mut sections = Vec::new();
    let mut section_names = BTreeSet::new();
    let mut previous_end = vm_address;
    for index in 0..count {
        let raw = &command[72 + index * 80..72 + (index + 1) * 80];
        let section_name = fixed_name(&raw[..16])?;
        if fixed_name(&raw[16..32])? != name || !section_names.insert(section_name.clone()) {
            return Err("section segment mismatch or duplicate section name".into());
        }
        let address = u64_at(raw, 32)?;
        let size = u64_at(raw, 40)?;
        let offset = u32_at(raw, 48)? as u64;
        let alignment = u32_at(raw, 52)?;
        let section_flags = u32_at(raw, 64)?;
        let indirect_start = u32_at(raw, 68)?;
        let stub_size = u32_at(raw, 72)?;
        let kind = section_flags & 0xff;
        if alignment > 14
            || address % (1u64 << alignment) != 0
            || !contains(vm_address, vm_size, address, size)
            || address < previous_end
            || u32_at(raw, 56)? != 0
            || u32_at(raw, 60)? != 0
            || u32_at(raw, 76)? != 0
        {
            return Err("invalid section range, alignment, or relocation metadata".into());
        }
        previous_end = address.checked_add(size).ok_or("section overflow")?;
        let valid = match (name.as_str(), section_name.as_str(), kind) {
            ("__TEXT", "__text", 0) => {
                section_flags & !0x8000_0400 == 0
                    && section_flags & 0x8000_0000 != 0
                    && address % 4 == 0
                    && size % 4 == 0
            }
            ("__TEXT", "__stubs", 8) => {
                section_flags == 0x8000_0408 && stub_size == 12 && size % 12 == 0
            }
            ("__TEXT", "__const", 0) => section_flags == 0,
            ("__TEXT", "__cstring", 2) => section_flags == 2,
            ("__DATA_CONST" | "__DATA", "__got", 6) => {
                section_flags == 6 && size % 8 == 0 && address % 8 == 0
            }
            ("__DATA_CONST" | "__DATA", "__mod_init_func", 9) => {
                section_flags == 9 && size % 8 == 0 && address % 8 == 0
            }
            ("__DATA_CONST" | "__DATA", "__const" | "__data", 0) => section_flags == 0,
            ("__DATA", "__bss" | "__common", 1) => section_flags == 1,
            _ => false,
        };
        if !valid {
            return Err(format!(
                "unsupported section {name},{section_name} flags={section_flags:#x}"
            ));
        }
        if kind != 6 && kind != 8 && (indirect_start != 0 || stub_size != 0) {
            return Err("unexpected section reserved fields".into());
        }
        if kind == 6 && stub_size != 0 {
            return Err("unexpected pointer-section stride".into());
        }
        if kind == 1 {
            if offset != 0 {
                return Err("zero-fill section carries a file offset".into());
            }
        } else if offset != file_offset + (address - vm_address)
            || !contains(file_offset, file_size, offset, size)
        {
            return Err("section file and VM ranges disagree".into());
        }
        sections.push(Section {
            name: section_name,
            address,
            size,
            flags: section_flags,
            indirect_start,
            stub_size,
        });
    }
    Ok(Segment {
        name,
        vm_address,
        vm_size,
        file_offset,
        file_size,
        initial_protection,
        maximum_protection,
        read_only_after_fixups,
        sections,
    })
}

fn parse_dylib(command: &[u8]) -> Result<String, String> {
    if command.len() < 32 || u32_at(command, 8)? != 24 {
        return Err("unsupported dylib name offset".into());
    }
    let mut cursor = Cursor::new(&command[24..]);
    let name = cursor.name()?;
    if cursor.remaining().iter().any(|byte| *byte != 0) {
        return Err("nonzero dylib command padding".into());
    }
    if u32_at(command, 20)? > u32_at(command, 16)? {
        return Err("invalid dylib compatibility version".into());
    }
    Ok(name)
}

fn parse_rebases(stream: &[u8], image: &Image) -> Result<Vec<u64>, String> {
    let mut cursor = Cursor::new(stream);
    let mut offsets = Vec::new();
    let mut segment = None;
    let mut address = 0;
    let mut pointer_type = false;
    while let Some(byte) = cursor.next() {
        let opcode = byte & 0xf0;
        let immediate = byte & 0xf;
        match opcode {
            0 if immediate == 0 => {
                cursor.zero_tail()?;
                return Ok(offsets);
            }
            0x10 if immediate == 1 => pointer_type = true,
            0x20 => {
                segment = Some(immediate as usize);
                address = cursor.uleb()?;
            }
            0x30 if immediate == 0 => address = add(address, cursor.uleb()?)?,
            0x40 => address = add(address, u64::from(immediate) * 8)?,
            0x50 => rebase_times(
                image,
                &mut offsets,
                segment,
                &mut address,
                pointer_type,
                u64::from(immediate),
                0,
            )?,
            0x60 if immediate == 0 => rebase_times(
                image,
                &mut offsets,
                segment,
                &mut address,
                pointer_type,
                cursor.uleb()?,
                0,
            )?,
            0x70 if immediate == 0 => rebase_times(
                image,
                &mut offsets,
                segment,
                &mut address,
                pointer_type,
                1,
                cursor.uleb()?,
            )?,
            0x80 if immediate == 0 => {
                let count = cursor.uleb()?;
                let skip = cursor.uleb()?;
                rebase_times(
                    image,
                    &mut offsets,
                    segment,
                    &mut address,
                    pointer_type,
                    count,
                    skip,
                )?;
            }
            _ => return Err("unsupported rebase opcode or pointer type".into()),
        }
    }
    if stream.is_empty() {
        Ok(offsets)
    } else {
        Err("unterminated rebase stream".into())
    }
}

fn rebase_times(
    image: &Image,
    offsets: &mut Vec<u64>,
    segment: Option<usize>,
    address: &mut u64,
    pointer_type: bool,
    count: u64,
    skip: u64,
) -> Result<(), String> {
    if !pointer_type
        || count == 0
        || count > MAX_FIXUPS as u64
        || offsets.len() + count as usize > MAX_FIXUPS
    {
        return Err("invalid or excessive pointer rebase count".into());
    }
    for _ in 0..count {
        offsets.push(fixup_offset(image, segment, *address)?);
        *address = add(*address, add(8, skip)?)?;
    }
    Ok(())
}

fn parse_binds(stream: &[u8], image: &Image) -> Result<Vec<Bind>, String> {
    let mut cursor = Cursor::new(stream);
    let mut bindings = Vec::new();
    let mut segment = None;
    let mut address = 0;
    let mut pointer_type = false;
    let mut ordinal = 0;
    let mut symbol = None;
    let mut addend = 0;
    while let Some(byte) = cursor.next() {
        let opcode = byte & 0xf0;
        let immediate = byte & 0xf;
        match opcode {
            0 if immediate == 0 => {
                cursor.zero_tail()?;
                return Ok(bindings);
            }
            0x10 if immediate != 0 => ordinal = u64::from(immediate),
            0x20 if immediate == 0 => ordinal = cursor.uleb()?,
            0x40 if immediate == 0 => {
                let name = cursor.name()?;
                if !valid_symbol(&name) {
                    return Err("unsupported import symbol name".into());
                }
                symbol = Some(name);
            }
            0x50 if immediate == 1 => pointer_type = true,
            0x60 if immediate == 0 => addend = cursor.sleb()?,
            0x70 => {
                segment = Some(immediate as usize);
                address = cursor.uleb()?;
            }
            0x80 if immediate == 0 => address = add(address, cursor.uleb()?)?,
            0x90 | 0xa0 | 0xb0 | 0xc0 => {
                if !pointer_type || ordinal == 0 || ordinal > image.dependencies.len() as u64 {
                    return Err(
                        "binding requires an ordinary declared dependency and pointer type".into(),
                    );
                }
                let symbol = symbol.as_ref().ok_or("binding has no symbol name")?;
                let (count, skip) = match opcode {
                    0x90 if immediate == 0 => (1, 0),
                    0xa0 if immediate == 0 => (1, cursor.uleb()?),
                    0xb0 => (1, u64::from(immediate) * 8),
                    0xc0 if immediate == 0 => (cursor.uleb()?, cursor.uleb()?),
                    _ => return Err("invalid binding opcode immediate".into()),
                };
                if count == 0
                    || count > MAX_FIXUPS as u64
                    || bindings.len() + count as usize > MAX_FIXUPS
                {
                    return Err("invalid or excessive pointer bind count".into());
                }
                for _ in 0..count {
                    bindings.push(Bind {
                        offset: fixup_offset(image, segment, address)?,
                        library_ordinal: ordinal as u8,
                        symbol: symbol.clone(),
                        addend,
                    });
                    address = add(address, add(8, skip)?)?;
                }
            }
            _ => return Err("unsupported bind opcode, weak symbol, or special ordinal".into()),
        }
    }
    if stream.is_empty() {
        Ok(bindings)
    } else {
        Err("unterminated bind stream".into())
    }
}

fn fixup_offset(image: &Image, index: Option<usize>, address: u64) -> Result<u64, String> {
    let segment = image
        .segments
        .get(index.ok_or("fixup has no segment")?)
        .ok_or("fixup segment index is out of range")?;
    let offset = add(segment.vm_address, address)?;
    if segment.initial_protection & 2 == 0
        || address % 8 != 0
        || !contains(0, segment.file_size, address, 8)
        || !image.has_section_address(offset, 8)
    {
        return Err("fixup must be an aligned, file-backed writable section pointer".into());
    }
    Ok(offset)
}

fn parse_exports(stream: &[u8], image: &Image) -> Result<BTreeMap<String, u64>, String> {
    if stream.is_empty() {
        return Err("export trie is required".into());
    }
    let mut pending = vec![(0usize, String::new(), 0usize)];
    let mut visited = BTreeSet::new();
    let mut node_ranges = Vec::new();
    let mut exports = BTreeMap::new();
    while let Some((offset, prefix, depth)) = pending.pop() {
        if offset >= stream.len()
            || depth > 64
            || !visited.insert(offset)
            || visited.len() > MAX_SYMBOLS * 2
        {
            return Err("invalid, cyclic, shared, or excessive export-trie node".into());
        }
        let mut cursor = Cursor::new(&stream[offset..]);
        let terminal_size =
            usize::try_from(cursor.uleb()?).map_err(|_| "export terminal overflow")?;
        if terminal_size > MAX_NAME || terminal_size > cursor.remaining().len() {
            return Err("invalid export-trie terminal size".into());
        }
        if terminal_size != 0 {
            let terminal = cursor.take(terminal_size)?;
            let mut entry = Cursor::new(terminal);
            if prefix.is_empty() || !valid_symbol(&prefix) || entry.uleb()? != 0 {
                return Err("only ordinary named export-trie definitions are supported".into());
            }
            let address = entry.uleb()?;
            if !entry.remaining().is_empty()
                || !image.has_section_address(address, 1)
                || exports.insert(prefix.clone(), address).is_some()
                || exports.len() > MAX_SYMBOLS
            {
                return Err("invalid or excessive export-trie definition".into());
            }
        }
        let count = cursor.next().ok_or("truncated export-trie edge count")?;
        let mut edges = BTreeSet::new();
        for _ in 0..count {
            let edge = cursor.name()?;
            if !edges.insert(edge.clone()) {
                return Err("duplicate export-trie edge".into());
            }
            let target =
                usize::try_from(cursor.uleb()?).map_err(|_| "export node offset overflow")?;
            let name = format!("{prefix}{edge}");
            if name.len() > MAX_NAME || pending.len() >= MAX_SYMBOLS * 2 {
                return Err("excessive export-trie name or work list".into());
            }
            pending.push((target, name, depth + 1));
        }
        let node_end = offset
            .checked_add(cursor.position)
            .ok_or("export node overflow")?;
        let node_range = offset..node_end;
        node_ranges.push(node_range);
    }
    if exports.is_empty() {
        return Err("no ordinary exports in controlled image".into());
    }
    // Check disjoint node ranges and zero padding in one bounded sorted pass.
    node_ranges.sort_unstable_by_key(|node| node.start);
    let mut prior_end = 0;
    for node in node_ranges {
        if node.start < prior_end {
            return Err("overlapping export-trie nodes".into());
        }
        if stream[prior_end..node.start].iter().any(|byte| *byte != 0) {
            return Err("unvisited nonzero export-trie bytes".into());
        }
        prior_end = node.end;
    }
    if stream[prior_end..].iter().any(|byte| *byte != 0) {
        return Err("unvisited nonzero export-trie bytes".into());
    }
    Ok(exports)
}

fn validate_symbols(
    bytes: &[u8],
    table: Symtab,
    dynamic: Dysymtab,
    image: &Image,
) -> Result<(), String> {
    let local_end = dynamic
        .local_start
        .checked_add(dynamic.local_count)
        .ok_or("local symbols overflow")?;
    let external_end = dynamic
        .external_start
        .checked_add(dynamic.external_count)
        .ok_or("external symbols overflow")?;
    let undefined_end = dynamic
        .undefined_start
        .checked_add(dynamic.undefined_count)
        .ok_or("undefined symbols overflow")?;
    if dynamic.local_start != 0
        || dynamic.external_start != local_end
        || dynamic.undefined_start != external_end
        || undefined_end != table.count
    {
        return Err("dynamic-symbol partitions must exactly cover the symbol table".into());
    }
    let strings = &bytes[range(bytes, table.strings as usize, table.string_size as usize)?];
    // Apple's linker conventionally starts the string table with space,NUL.
    if !(strings.first() == Some(&0) || strings.starts_with(b" \0")) || strings.last() != Some(&0) {
        return Err("invalid Mach-O symbol string table".into());
    }
    let section_count = image
        .segments
        .iter()
        .map(|segment| segment.sections.len())
        .sum::<usize>();
    let sections: Vec<_> = image
        .segments
        .iter()
        .flat_map(|segment| &segment.sections)
        .collect();
    let mut undefined = BTreeSet::new();
    let mut symbol_names = BTreeSet::new();
    let mut symbol_imports = Vec::new();
    if image.exports.len() != dynamic.external_count as usize {
        return Err("export trie and external symbol counts disagree".into());
    }
    for index in 0..table.count {
        let entry = table.symbols as usize + index as usize * 16;
        let string_index = u32_at(bytes, entry)? as usize;
        if string_index >= strings.len() {
            return Err("symbol string index is out of range".into());
        }
        let mut cursor = Cursor::new(&strings[string_index..]);
        let name = cursor.name()?;
        let kind = bytes[entry + 4];
        let section = bytes[entry + 5] as usize;
        let desc = u16_at(bytes, entry + 6)?;
        let value = u64_at(bytes, entry + 8)?;
        if !valid_symbol(&name)
            || !symbol_names.insert(name.clone())
            || kind & 0xe0 != 0
            || desc & 0xff != 0
        {
            return Err("debug, weak, lazy, or special Mach-O symbols are unsupported".into());
        }
        if index >= dynamic.undefined_start {
            let ordinal = desc >> 8;
            if kind != 1
                || section != 0
                || value != 0
                || ordinal == 0
                || ordinal as usize > image.dependencies.len()
            {
                return Err("undefined symbol requires ordinary two-level library binding".into());
            }
            let import = (ordinal as u8, name);
            undefined.insert(import.clone());
            symbol_imports.push(Some(import));
        } else {
            let expected_kind = if index >= dynamic.external_start {
                0xf
            } else {
                0xe
            };
            if kind != expected_kind
                || desc != 0
                || section == 0
                || section > section_count
                || !contains(
                    sections[section - 1].address,
                    sections[section - 1].size,
                    value,
                    1,
                )
            {
                return Err(
                    "only ordinary in-section Mach-O symbol definitions are supported".into(),
                );
            }
            if index >= dynamic.external_start && image.exports.get(&name) != Some(&value) {
                return Err("external symbol and export trie disagree".into());
            }
            symbol_imports.push(None);
        }
    }
    let bound: BTreeSet<_> = image
        .binds
        .iter()
        .map(|bind| (bind.library_ordinal, bind.symbol.clone()))
        .collect();
    if bound != undefined {
        return Err("symbol-table imports and eager bindings disagree".into());
    }
    for index in 0..dynamic.indirect_count {
        let symbol = u32_at(bytes, dynamic.indirect as usize + index as usize * 4)?;
        if symbol >= table.count {
            return Err("special or out-of-range indirect symbol index".into());
        }
    }
    for section in sections {
        let kind = section.flags & 0xff;
        if kind == 6 || kind == 8 {
            let stride = if kind == 6 {
                8
            } else {
                u64::from(section.stub_size)
            };
            let count = section.size / stride;
            if u64::from(section.indirect_start)
                .checked_add(count)
                .ok_or("indirect section overflow")?
                > u64::from(dynamic.indirect_count)
            {
                return Err("indirect symbol section exceeds its table".into());
            }
            if kind == 6
                && (0..count).any(|index| {
                    !image
                        .binds
                        .iter()
                        .any(|bind| bind.offset == section.address + index * 8)
                })
            {
                return Err("non-lazy pointer section must contain only eager bindings".into());
            }
            for index in 0..count {
                let entry = dynamic.indirect as usize
                    + (u64::from(section.indirect_start) + index) as usize * 4;
                let symbol = u32_at(bytes, entry)? as usize;
                let import = symbol_imports
                    .get(symbol)
                    .and_then(Option::as_ref)
                    .ok_or("stub or GOT points to a non-import symbol")?;
                if kind == 6 {
                    let offset = section.address + index * 8;
                    let binding = image
                        .binds
                        .iter()
                        .find(|binding| binding.offset == offset)
                        .ok_or("GOT pointer lacks a binding")?;
                    if binding.library_ordinal != import.0 || binding.symbol != import.1 {
                        return Err("indirect GOT symbol and eager binding disagree".into());
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_function_starts(stream: &[u8], image: &Image) -> Result<(), String> {
    if stream.is_empty() {
        return Ok(());
    }
    let mut cursor = Cursor::new(stream);
    let mut address = 0;
    for _ in 0..MAX_SYMBOLS {
        let delta = cursor.uleb()?;
        if delta == 0 {
            cursor.zero_tail()?;
            return Ok(());
        }
        address = add(address, delta)?;
        if !image.is_executable(address) {
            return Err("function-start metadata points outside __text".into());
        }
    }
    Err("excessive function-start metadata".into())
}

fn validate_data_in_code(stream: &[u8], image: &Image) -> Result<(), String> {
    if stream.len() % 8 != 0 || stream.len() / 8 > MAX_SYMBOLS {
        return Err("invalid data-in-code table".into());
    }
    let mut previous_end = 0;
    for entry in stream.chunks_exact(8) {
        let file_offset = u32_at(entry, 0)? as u64;
        let length = u16_at(entry, 4)? as u64;
        let kind = u16_at(entry, 6)?;
        let text = &image.segments[0];
        if !(1..=5).contains(&kind)
            || length == 0
            || file_offset < previous_end
            || !text.sections.iter().any(|section| {
                section.name == "__text"
                    && contains(section.address, section.size, file_offset, length)
            })
        {
            return Err("invalid or overlapping data-in-code range".into());
        }
        previous_end = add(file_offset, length)?;
    }
    Ok(())
}

fn add_metadata_range(
    bytes: &[u8],
    offset: u32,
    length: u32,
    prior: &mut Vec<Range<usize>>,
) -> Result<Range<usize>, String> {
    if length as usize > MAX_METADATA_BYTES {
        return Err("invalid or excessive Mach-O metadata range".into());
    }
    let payload = range(bytes, offset as usize, length as usize)?;
    if !payload.is_empty() {
        if prior.iter().any(|range| overlaps(range, &payload)) {
            return Err("overlapping Mach-O metadata ranges".into());
        }
        prior.push(payload.clone());
    }
    Ok(payload)
}

fn stream(bytes: &[u8], descriptor: (u32, u32)) -> Result<&[u8], String> {
    Ok(&bytes[range(bytes, descriptor.0 as usize, descriptor.1 as usize)?])
}

fn contains(start: u64, size: u64, offset: u64, length: u64) -> bool {
    offset >= start
        && offset
            .checked_add(length)
            .zip(start.checked_add(size))
            .is_some_and(|(end, limit)| end <= limit)
}

fn overlaps(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}
fn add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "Mach-O address overflow".into())
}
fn exact_size(command: &[u8], expected: usize) -> Result<(), String> {
    if command.len() == expected {
        Ok(())
    } else {
        Err("unexpected Mach-O load-command size".into())
    }
}
fn range(bytes: &[u8], offset: usize, length: usize) -> Result<Range<usize>, String> {
    let end = offset.checked_add(length).ok_or("Mach-O range overflow")?;
    if end > bytes.len() {
        Err("Mach-O range is outside image bytes".into())
    } else {
        Ok(offset..end)
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or("integer offset overflow")?)
        .ok_or("truncated Mach-O integer")?;
    Ok(u16::from_le_bytes(
        value.try_into().map_err(|_| "integer width")?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or("integer offset overflow")?)
        .ok_or("truncated Mach-O integer")?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| "integer width")?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset.checked_add(8).ok_or("integer offset overflow")?)
        .ok_or("truncated Mach-O integer")?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| "integer width")?,
    ))
}
fn fixed_name(raw: &[u8]) -> Result<String, String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if end == 0
        || raw[end..].iter().any(|byte| *byte != 0)
        || !raw[..end].iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err("invalid fixed-size Mach-O name".into());
    }
    String::from_utf8(raw[..end].to_vec()).map_err(|_| "non-ASCII Mach-O name".into())
}
fn valid_symbol(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$'))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
    fn next(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.position).copied()?;
        self.position += 1;
        Some(byte)
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("metadata cursor overflow")?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated metadata payload")?;
        self.position = end;
        Ok(value)
    }
    fn zero_tail(&self) -> Result<(), String> {
        if self.remaining().iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err("nonzero bytes after metadata terminator".into())
        }
    }
    fn name(&mut self) -> Result<String, String> {
        let remaining = self.remaining();
        let end = remaining
            .iter()
            .take(MAX_NAME + 1)
            .position(|byte| *byte == 0)
            .ok_or("unterminated or excessive metadata name")?;
        if end == 0 || !remaining[..end].iter().all(|byte| byte.is_ascii_graphic()) {
            return Err("empty or non-ASCII metadata name".into());
        }
        let name =
            String::from_utf8(remaining[..end].to_vec()).map_err(|_| "invalid metadata name")?;
        self.position += end + 1;
        Ok(name)
    }
    fn uleb(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.next().ok_or("truncated ULEB128")?;
            let digit = u64::from(byte & 0x7f);
            if shift == 63 && digit > 1 {
                return Err("ULEB128 overflow".into());
            }
            value |= digit << shift;
            if byte & 0x80 == 0 {
                if shift != 0 && digit == 0 {
                    return Err("noncanonical ULEB128".into());
                }
                return Ok(value);
            }
        }
        Err("ULEB128 overflow".into())
    }
    fn sleb(&mut self) -> Result<i64, String> {
        let mut value = 0u64;
        let mut prior = 0u8;
        for shift in (0..=63).step_by(7) {
            let byte = self.next().ok_or("truncated SLEB128")?;
            let digit = byte & 0x7f;
            if shift == 63 && digit != 0 && digit != 0x7f {
                return Err("SLEB128 overflow".into());
            }
            value |= u64::from(digit) << shift;
            if byte & 0x80 == 0 {
                if shift != 0
                    && ((digit == 0 && prior & 0x40 == 0) || (digit == 0x7f && prior & 0x40 != 0))
                {
                    return Err("noncanonical SLEB128".into());
                }
                let width = shift + 7;
                if width < 64 && byte & 0x40 != 0 {
                    value |= u64::MAX << width;
                }
                return Ok(value as i64);
            }
            prior = byte;
        }
        Err("SLEB128 overflow".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT_ADDRESS: u64 = 0x1000;
    const LINKEDIT: usize = 0xc000;

    struct Fixture {
        bytes: Vec<u8>,
        commands: BTreeMap<u32, usize>,
        rebase: usize,
        bind: usize,
        export: usize,
        symbols: usize,
        strings: usize,
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn uleb(mut value: u64) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let digit = (value & 0x7f) as u8;
            value >>= 7;
            result.push(digit | if value == 0 { 0 } else { 0x80 });
            if value == 0 {
                return result;
            }
        }
    }
    fn fixed(bytes: &mut [u8], offset: usize, name: &str) {
        bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    }
    fn section(
        name: &str,
        segment: &str,
        address: u64,
        size: u64,
        offset: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut raw = vec![0; 80];
        fixed(&mut raw, 0, name);
        fixed(&mut raw, 16, segment);
        put64(&mut raw, 32, address);
        put64(&mut raw, 40, size);
        put32(&mut raw, 48, offset);
        put32(
            &mut raw,
            52,
            if flags & 0xff == 9 || flags & 0xff == 6 {
                3
            } else {
                2
            },
        );
        put32(&mut raw, 64, flags);
        raw
    }
    fn segment(
        name: &str,
        address: u64,
        file_size: u64,
        protection: u32,
        sections: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let mut raw = vec![0; 72];
        put32(&mut raw, 0, 0x19);
        put32(&mut raw, 4, (72 + sections.len() * 80) as u32);
        fixed(&mut raw, 8, name);
        put64(&mut raw, 24, address);
        put64(&mut raw, 32, PAGE_SIZE);
        put64(&mut raw, 40, address);
        put64(&mut raw, 48, file_size);
        put32(&mut raw, 56, protection);
        put32(&mut raw, 60, protection);
        put32(&mut raw, 64, sections.len() as u32);
        put32(&mut raw, 68, if name == "__DATA_CONST" { 0x10 } else { 0 });
        for section in sections {
            raw.extend(section);
        }
        raw
    }
    fn command(kind: u32, size: usize) -> Vec<u8> {
        let mut raw = vec![0; size];
        put32(&mut raw, 0, kind);
        put32(&mut raw, 4, size as u32);
        raw
    }
    fn dylib(kind: u32, name: &str) -> Vec<u8> {
        let mut raw = command(kind, (24 + name.len() + 1).next_multiple_of(8));
        put32(&mut raw, 8, 24);
        fixed(&mut raw, 24, name);
        raw
    }
    fn simple_trie() -> Vec<u8> {
        let names = ["_answer", "_data"];
        let mut root = vec![0, 2];
        let root_size = 2 + names.iter().map(|name| name.len() + 2).sum::<usize>();
        let mut leaves = Vec::new();
        for (name, address) in names.into_iter().zip([TEXT_ADDRESS + 4, 0x8000]) {
            root.extend(name.as_bytes());
            root.push(0);
            root.extend(uleb((root_size + leaves.len()) as u64));
            let mut terminal = vec![0];
            terminal.extend(uleb(address));
            leaves.extend(uleb(terminal.len() as u64));
            leaves.extend(terminal);
            leaves.push(0);
        }
        root.extend(leaves);
        root
    }
    fn make_fixture() -> Fixture {
        let rebase_data = [0x11, 0x21, 0, 0x51, 0];
        let bind_data = [
            0x11, 0x40, b'_', b'g', b'e', b't', b'p', b'i', b'd', 0, 0x51, 0x71, 8, 0x90, 0,
        ];
        let trie = simple_trie();
        let rebase = LINKEDIT;
        let bind = rebase + rebase_data.len();
        let export = bind + bind_data.len();
        let symbols = (export + trie.len()).next_multiple_of(8);
        let strings = symbols + 5 * 16;
        let string_data = b"\0_ctor\0_state\0_answer\0_data\0_getpid\0";
        let signature = (strings + string_data.len()).next_multiple_of(16);
        let final_length = signature + 32;
        let mut commands = vec![
            segment(
                "__TEXT",
                0,
                PAGE_SIZE,
                5,
                vec![section(
                    "__text",
                    "__TEXT",
                    TEXT_ADDRESS,
                    12,
                    TEXT_ADDRESS as u32,
                    0x8000_0400,
                )],
            ),
            segment(
                "__DATA_CONST",
                0x4000,
                PAGE_SIZE,
                3,
                vec![
                    section("__mod_init_func", "__DATA_CONST", 0x4000, 8, 0x4000, 9),
                    section("__got", "__DATA_CONST", 0x4008, 8, 0x4008, 6),
                ],
            ),
            segment(
                "__DATA",
                0x8000,
                PAGE_SIZE,
                3,
                vec![
                    section("__data", "__DATA", 0x8000, 8, 0x8000, 0),
                    section("__bss", "__DATA", 0x8008, 8, 0, 1),
                ],
            ),
            segment(
                "__LINKEDIT",
                LINKEDIT as u64,
                (final_length - LINKEDIT) as u64,
                1,
                vec![],
            ),
            dylib(0xd, "@loader_path/libfixture.dylib"),
            dylib(0xc, "/usr/lib/libSystem.B.dylib"),
        ];
        let mut dyld = command(0x8000_0022, 48);
        for (field, value) in [
            (8, rebase),
            (12, rebase_data.len()),
            (16, bind),
            (20, bind_data.len()),
            (40, export),
            (44, trie.len()),
        ] {
            put32(&mut dyld, field, value as u32);
        }
        commands.push(dyld);
        let mut symtab = command(2, 24);
        for (field, value) in [
            (8, symbols),
            (12, 5),
            (16, strings),
            (20, string_data.len()),
        ] {
            put32(&mut symtab, field, value as u32);
        }
        commands.push(symtab);
        let mut dynamic = command(0xb, 80);
        for (field, value) in [
            (12, 2),
            (16, 2),
            (20, 2),
            (24, 4),
            (28, 1),
            (56, signature - 4),
            (60, 1),
        ] {
            put32(&mut dynamic, field, value as u32);
        }
        commands.push(dynamic);
        let mut build = command(0x32, 24);
        put32(&mut build, 8, 1);
        put32(&mut build, 12, 13 << 16);
        put32(&mut build, 16, 27 << 16);
        commands.push(build);
        let mut code_signature = command(0x1d, 16);
        put32(&mut code_signature, 8, signature as u32);
        put32(&mut code_signature, 12, 32);
        commands.push(code_signature);
        let mut bytes = vec![0; final_length];
        put32(&mut bytes, 0, 0xfeed_facf);
        put32(&mut bytes, 4, 0x0100_000c);
        put32(&mut bytes, 12, 6);
        put32(&mut bytes, 16, commands.len() as u32);
        put32(
            &mut bytes,
            20,
            commands.iter().map(Vec::len).sum::<usize>() as u32,
        );
        put32(&mut bytes, 24, 0x10_0085);
        let mut command_offsets = BTreeMap::new();
        let mut position = 32;
        for command in commands {
            command_offsets.insert(u32_at(&command, 0).unwrap(), position);
            bytes[position..position + command.len()].copy_from_slice(&command);
            position += command.len();
        }
        bytes[rebase..rebase + rebase_data.len()].copy_from_slice(&rebase_data);
        bytes[bind..bind + bind_data.len()].copy_from_slice(&bind_data);
        bytes[export..export + trie.len()].copy_from_slice(&trie);
        bytes[strings..strings + string_data.len()].copy_from_slice(string_data);
        for (index, (string, kind, section, desc, value)) in [
            (1, 0xe, 1, 0, TEXT_ADDRESS),
            (7, 0xe, 5, 0, 0x8008),
            (14, 0xf, 1, 0, TEXT_ADDRESS + 4),
            (22, 0xf, 4, 0, 0x8000),
            (28, 1, 0, 0x100, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let entry = symbols + index * 16;
            put32(&mut bytes, entry, string);
            bytes[entry + 4] = kind;
            bytes[entry + 5] = section;
            bytes[entry + 6..entry + 8].copy_from_slice(&(desc as u16).to_le_bytes());
            put64(&mut bytes, entry + 8, value);
        }
        put32(&mut bytes, signature - 4, 4);
        put64(&mut bytes, 0x4000, TEXT_ADDRESS);
        put64(&mut bytes, 0x8000, 7);
        Fixture {
            bytes,
            commands: command_offsets,
            rebase,
            bind,
            export,
            symbols,
            strings,
        }
    }

    #[test]
    fn accepts_bounded_classic_c_image_without_authenticating_signature() {
        let fixture = make_fixture();
        let image = parse(&fixture.bytes).unwrap();
        assert_eq!(image.vm_size, PAGE_SIZE * 4);
        assert_eq!(image.rebases, [0x4000]);
        assert_eq!(image.constructors, [0x4000]);
        assert_eq!(
            image.binds,
            [Bind {
                offset: 0x4008,
                library_ordinal: 1,
                symbol: "_getpid".into(),
                addend: 0
            }]
        );
        assert_eq!(image.exports["_answer"], TEXT_ADDRESS + 4);
        assert!(image.is_executable(TEXT_ADDRESS));
        assert!(!image.is_executable(0x8000));
        assert!(image.segments[1].read_only_after_fixups);
        assert_eq!(image.install_name, "@loader_path/libfixture.dylib");
        assert!(image.code_signature.is_some());
    }

    #[test]
    fn rejects_all_truncations_without_panicking() {
        let fixture = make_fixture();
        for length in [
            0,
            1,
            28,
            31,
            32,
            40,
            200,
            0x1000,
            LINKEDIT,
            fixture.bytes.len() - 1,
        ] {
            assert!(
                parse(&fixture.bytes[..length]).is_err(),
                "accepted length {length}"
            );
        }
    }
    #[test]
    fn rejects_wrong_architecture_subtype_and_file_type() {
        for (offset, value) in [(0, 0xcffa_edfe), (4, 0x0100_0007), (8, 2), (12, 2)] {
            let mut fixture = make_fixture();
            put32(&mut fixture.bytes, offset, value);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_unknown_or_weak_header_flags() {
        for flag in [0x100, 0x8000, 0x10000, 0x800000, 0x80000000] {
            let mut fixture = make_fixture();
            put32(&mut fixture.bytes, 24, 0x10_0085 | flag);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_chained_fixups_and_runtime_registration_commands() {
        for command in [0x8000_0034, 0x8000_0033, 0x1a, 0x8000_001c, 0x31, 0x2c] {
            let mut fixture = make_fixture();
            let offset = fixture.commands[&0x32];
            put32(&mut fixture.bytes, offset, command);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_malformed_and_oversized_load_command_metadata() {
        for (field, value) in [(16, 65), (20, 65537), (28, 1)] {
            let mut fixture = make_fixture();
            put32(&mut fixture.bytes, field, value);
            assert!(parse(&fixture.bytes).is_err());
        }
        for size in [0, 7, 73, u32::MAX] {
            let mut fixture = make_fixture();
            put32(&mut fixture.bytes, 36, size);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_overlapping_or_non_16k_segments() {
        for (field, value) in [(24, 1), (32, 4096), (40, 4096), (48, PAGE_SIZE + 1)] {
            let mut fixture = make_fixture();
            put64(&mut fixture.bytes, 32 + field, value);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_writable_executable_and_extra_maximum_protections() {
        for (field, value) in [(56, 7), (60, 7), (56, 0xffffffff)] {
            let mut fixture = make_fixture();
            put32(&mut fixture.bytes, 32 + field, value);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_text_header_overlap_and_section_overlap() {
        let mut fixture = make_fixture();
        put64(&mut fixture.bytes, 32 + 72 + 32, 0);
        put32(&mut fixture.bytes, 32 + 72 + 48, 0);
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        let data_const = 32 + 152;
        put64(&mut fixture.bytes, data_const + 72 + 80 + 32, 0x4000);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_tls_objc_unwind_and_modern_initializer_sections() {
        for (name, flags) in [
            ("__thread_vars", 0x13),
            ("__objc_data", 0),
            ("__unwind_info", 0),
            ("__init_offsets", 0x16),
        ] {
            let mut fixture = make_fixture();
            let offset = 32 + 72;
            fixture.bytes[offset..offset + 16].fill(0);
            fixed(&mut fixture.bytes, offset, name);
            put32(&mut fixture.bytes, offset + 64, flags);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_lazy_and_weak_fixup_streams() {
        for field in [24, 28, 32, 36] {
            let mut fixture = make_fixture();
            let offset = fixture.commands[&0x8000_0022];
            put32(&mut fixture.bytes, offset + field, 1);
            assert!(parse(&fixture.bytes).is_err());
        }
    }
    #[test]
    fn rejects_overlapping_and_out_of_image_linkedit_ranges() {
        for field in [8, 16, 40] {
            let mut fixture = make_fixture();
            let offset = fixture.commands[&0x8000_0022];
            put32(&mut fixture.bytes, offset + field, u32::MAX);
            assert!(parse(&fixture.bytes).is_err());
        }
        let mut fixture = make_fixture();
        let offset = fixture.commands[&0x8000_0022];
        put32(&mut fixture.bytes, offset + 16, fixture.rebase as u32);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_wrong_rebase_type_or_out_of_image_target() {
        for value in [0x12, 0x1f] {
            let mut fixture = make_fixture();
            fixture.bytes[fixture.rebase] = value;
            assert!(parse(&fixture.bytes).is_err());
        }
        let mut fixture = make_fixture();
        put64(&mut fixture.bytes, 0x4000, 0xffff_ffff);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_text_fixups_and_misaligned_pointer_slots() {
        let mut fixture = make_fixture();
        fixture.bytes[fixture.rebase + 1] = 0x20;
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        fixture.bytes[fixture.rebase + 2] = 1;
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_rebase_count_expansion_and_nonzero_tail() {
        let image = parse(&make_fixture().bytes).unwrap();
        assert!(parse_rebases(&[0x11, 0x21, 0, 0x60, 0xff, 0xff, 0x7f, 0], &image).is_err());
        assert!(parse_rebases(&[0, 1], &image).is_err());
        assert!(parse_rebases(&[0x11], &image).is_err());
    }
    #[test]
    fn rejects_ctor_targets_outside_text_and_missing_rebase() {
        let mut fixture = make_fixture();
        put64(&mut fixture.bytes, 0x4000, 0x8000);
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        fixture.bytes[fixture.rebase..fixture.rebase + 5].fill(0);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_special_ordinals_weak_symbols_and_threaded_bindings() {
        for value in [0x30, 0x3f, 0xd0, 0x10, 0x12] {
            let mut fixture = make_fixture();
            fixture.bytes[fixture.bind] = value;
            assert!(parse(&fixture.bytes).is_err());
        }
        let mut fixture = make_fixture();
        fixture.bytes[fixture.bind + 1] = 0x41;
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_nonnull_imports_and_unterminated_import_names() {
        let mut fixture = make_fixture();
        put64(&mut fixture.bytes, 0x4008, 0x1000);
        assert!(parse(&fixture.bytes).is_err());
        let image = parse(&make_fixture().bytes).unwrap();
        assert!(parse_binds(&[0x11, 0x40, b'_', b'a'], &image).is_err());
    }
    #[test]
    fn rejects_duplicate_and_overlapping_fixup_writes() {
        let mut fixture = make_fixture();
        fixture.bytes[fixture.bind + 12] = 0;
        assert!(parse(&fixture.bytes).is_err());
        let image = parse(&make_fixture().bytes).unwrap();
        let duplicate = [0x11, 0x21, 0, 0x51, 0x21, 0, 0x51, 0];
        assert_eq!(parse_rebases(&duplicate, &image).unwrap(), [0x4000, 0x4000]);
    }
    #[test]
    fn rejects_cyclic_overlapping_or_out_of_range_export_trie() {
        let image = parse(&make_fixture().bytes).unwrap();
        for trie in [
            vec![0, 1, b'a', 0, 0],
            vec![0, 1, b'a', 0, 4],
            vec![0, 1, b'a', 0, 127],
        ] {
            assert!(parse_exports(&trie, &image).is_err());
        }
    }
    #[test]
    fn rejects_weak_tls_reexport_and_resolver_exports() {
        let image = parse(&make_fixture().bytes).unwrap();
        for flag in [1, 2, 4, 8, 16, 32] {
            let mut trie = simple_trie();
            let first_node = 2 + "_answer".len() + 2 + "_data".len() + 2;
            trie[first_node + 1] = flag;
            assert!(parse_exports(&trie, &image).is_err());
        }
    }
    #[test]
    fn rejects_hidden_export_trie_bytes_and_export_symbol_disagreement() {
        let image = parse(&make_fixture().bytes).unwrap();
        let mut trie = simple_trie();
        trie.push(1);
        assert!(parse_exports(&trie, &image).is_err());
        let mut fixture = make_fixture();
        put64(
            &mut fixture.bytes,
            fixture.symbols + 2 * 16 + 8,
            TEXT_ADDRESS + 8,
        );
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        fixture.bytes[fixture.export] = 255;
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_symbol_table_import_mismatch_and_weak_descriptor() {
        let mut fixture = make_fixture();
        fixture.bytes[fixture.strings + 29] = b'x';
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        fixture.bytes[fixture.symbols + 4 * 16 + 6] = 0x40;
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_bad_symbol_partition_strings_and_indirect_index() {
        let mut fixture = make_fixture();
        let offset = fixture.commands[&0xb];
        put32(&mut fixture.bytes, offset + 24, 3);
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        put32(&mut fixture.bytes, fixture.symbols, u32::MAX);
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        let offset = fixture.commands[&0xb];
        let indirect = u32_at(&fixture.bytes, offset + 56).unwrap() as usize;
        put32(&mut fixture.bytes, indirect, 0x8000_0000);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn rejects_nonzero_bss_and_missing_or_nonterminal_signature_metadata() {
        let mut fixture = make_fixture();
        fixture.bytes[0x8008] = 1;
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        let offset = fixture.commands[&0x1d];
        put32(&mut fixture.bytes, offset, 0x26);
        assert!(parse(&fixture.bytes).is_err());
        let mut fixture = make_fixture();
        fixture.bytes.push(0);
        assert!(parse(&fixture.bytes).is_err());
    }
    #[test]
    fn validates_inert_function_start_and_data_in_code_metadata() {
        let image = parse(&make_fixture().bytes).unwrap();
        let mut starts = uleb(TEXT_ADDRESS);
        starts.extend([4, 4, 0]);
        validate_function_starts(&starts, &image).unwrap();
        assert!(validate_function_starts(&[1, 0], &image).is_err());
        assert!(validate_function_starts(&[0, 1], &image).is_err());
        let mut entry = vec![0; 8];
        put32(&mut entry, 0, TEXT_ADDRESS as u32);
        entry[4..6].copy_from_slice(&4u16.to_le_bytes());
        entry[6..8].copy_from_slice(&1u16.to_le_bytes());
        validate_data_in_code(&entry, &image).unwrap();
        let mut overlap = entry.clone();
        overlap.extend(entry);
        assert!(validate_data_in_code(&overlap, &image).is_err());
        assert!(validate_data_in_code(&[0; 7], &image).is_err());
    }
    #[test]
    fn uleb_and_sleb_are_bounded_and_canonical() {
        for value in [0, 127, 128, u32::MAX as u64, u64::MAX] {
            assert_eq!(Cursor::new(&uleb(value)).uleb().unwrap(), value);
        }
        for malformed in [
            &[0x80][..],
            &[0x80, 0],
            &[0xff; 11],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2],
        ] {
            assert!(Cursor::new(malformed).uleb().is_err());
        }
        for (encoded, value) in [
            (&[0][..], 0),
            (&[0x7f][..], -1),
            (&[0x80, 0x7f][..], -128),
            (&[0xff, 0][..], 127),
        ] {
            assert_eq!(Cursor::new(encoded).sleb().unwrap(), value);
        }
        assert!(Cursor::new(&[0x80, 0]).sleb().is_err());
        assert!(Cursor::new(&[0xff, 0x7f]).sleb().is_err());
    }
    #[test]
    fn validates_supported_rebase_address_and_repeat_forms() {
        let image = parse(&make_fixture().bytes).unwrap();
        for stream in [
            vec![0x11, 0x22, 0, 0x60, 1, 0],
            vec![0x11, 0x22, 0, 0x70, 0, 0],
            vec![0x11, 0x22, 0, 0x80, 1, 0, 0],
            vec![0x11, 0x22, 0, 0x30, 8, 0x51, 0],
            vec![0x11, 0x22, 0, 0x41, 0x51, 0],
        ] {
            let rebases = parse_rebases(&stream, &image).unwrap();
            assert_eq!(rebases.len(), 1);
            assert!(rebases[0] == 0x8000 || rebases[0] == 0x8008);
        }
    }
    #[test]
    fn validates_supported_binding_address_addend_and_repeat_forms() {
        let image = parse(&make_fixture().bytes).unwrap();
        for ending in [vec![0x90], vec![0xa0, 0], vec![0xb0], vec![0xc0, 1, 0]] {
            let mut stream = vec![0x20, 1, 0x40];
            stream.extend(b"_getpid\0");
            stream.extend([0x51, 0x60, 0x7f, 0x72, 0, 0x80, 8]);
            stream.extend(ending);
            stream.push(0);
            let bindings = parse_binds(&stream, &image).unwrap();
            assert_eq!(
                bindings,
                [Bind {
                    offset: 0x8008,
                    library_ordinal: 1,
                    symbol: "_getpid".into(),
                    addend: -1
                }]
            );
        }
    }
    #[test]
    fn rejects_oversized_names_tables_and_invalid_minimum_versions() {
        let mut name = vec![b'a'; MAX_NAME + 1];
        name.push(0);
        assert!(Cursor::new(&name).name().is_err());
        let mut fixture = make_fixture();
        let offset = fixture.commands[&2];
        put32(&mut fixture.bytes, offset + 12, MAX_SYMBOLS as u32 + 1);
        assert!(parse(&fixture.bytes).is_err());
        for minimum in [10 << 16, 28 << 16] {
            let mut fixture = make_fixture();
            let offset = fixture.commands[&0x32];
            put32(&mut fixture.bytes, offset + 12, minimum);
            assert!(parse(&fixture.bytes).is_err());
        }
        assert_eq!(
            parse(&make_fixture().bytes).unwrap().minimum_os_version,
            13 << 16
        );
    }
    #[test]
    fn single_byte_metadata_mutations_never_panic() {
        let fixture = make_fixture();
        let command_end = 32 + u32_at(&fixture.bytes, 20).unwrap() as usize;
        for index in (0..command_end)
            .step_by(7)
            .chain(LINKEDIT..fixture.bytes.len())
        {
            for replacement in [0, 0x80, 0xff] {
                let mut bytes = fixture.bytes.clone();
                bytes[index] = replacement;
                assert!(
                    std::panic::catch_unwind(|| parse(&bytes)).is_ok(),
                    "panic at {index} byte={replacement}"
                );
            }
        }
    }
}
