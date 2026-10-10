//! Read a bounded tar stream without creating files or retaining runtime payloads.
//!
//! Headers and extension records are parsed here rather than by an extractor:
//! otherwise GNU/PAX records can allocate before the caller checks their size.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::io::{self, Read};

use serde::Serialize;
use sha2::{Digest, Sha256};

const BLOCK_BYTES: usize = 512;
const MAX_EXTENSION_BYTES: u64 = 16 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_LINK_DEPTH: usize = 128;

/// Maximum combined payload size retained by selective inventory readers.
pub const MAX_SELECTED_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_entries: usize,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_tar_bytes: u64,
    pub max_metadata_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            max_member_bytes: 256 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_tar_bytes: 3 * 1024 * 1024 * 1024,
            max_metadata_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    RegularFile,
    Directory,
    Symlink,
    Hardlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub sha256: Option<String>,
    pub link_target: Option<String>,
    pub resolved_target: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Inventory {
    pub entries: BTreeMap<String, Entry>,
    pub metadata: Option<Vec<u8>>,
    pub decompressed_bytes: u64,
    /// At most the first 64 bytes, only for members with a binary magic value.
    pub binary_prefixes: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug)]
pub struct SelectedInventory {
    pub inventory: Inventory,
    /// Exact regular-file payloads keyed by their canonical archive names.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Inventory a decompressed stock PBS tar stream. Every payload is consumed and
/// hashed; only `python/PYTHON.json` and small binary prefixes are retained.
pub fn read_inventory<R: Read>(reader: R, limits: &Limits) -> Result<Inventory, String> {
    Ok(read_selected(reader, limits, &BTreeSet::new(), 0)?.inventory)
}

/// Retain selected regular files while validating and hashing the entire tar.
/// Selection never follows symlinks or hardlinks and never consults host paths.
/// Bytes are returned only after all members, links and end padding validate.
pub fn read_selected<R: Read>(
    reader: R,
    limits: &Limits,
    selection: &BTreeSet<String>,
    max_selected_bytes: u64,
) -> Result<SelectedInventory, String> {
    if max_selected_bytes > MAX_SELECTED_BYTES {
        return Err("selected PBS payload bound exceeds 128 MiB".into());
    }
    if selection.len() > limits.max_entries {
        return Err("selected PBS member count exceeds the header count limit".into());
    }
    for path in selection {
        member_path(path, false)?;
    }
    let mut reader = BoundedReader {
        reader,
        consumed: 0,
        limit: limits.max_tar_bytes,
    };
    let mut inventory = Inventory {
        entries: BTreeMap::new(),
        metadata: None,
        decompressed_bytes: 0,
        binary_prefixes: BTreeMap::new(),
    };
    let mut links = BTreeSet::new();
    let mut pending = Extensions::default();
    let mut headers = 0usize;
    let mut total = 0u64;
    let mut selected_bytes = 0u64;
    let mut files = BTreeMap::new();

    loop {
        let mut header = [0u8; BLOCK_BYTES];
        reader.exact(&mut header, "tar header or end marker")?;
        if header.iter().all(|byte| *byte == 0) {
            if pending.present {
                return Err("tar extensions have no following member".into());
            }
            reader.exact(&mut header, "second tar end marker")?;
            if header.iter().any(|byte| *byte != 0) {
                return Err("tar requires two consecutive zero end markers".into());
            }
            reader.finish_padding()?;
            inventory.decompressed_bytes = reader.consumed;
            resolve_links(&mut inventory.entries, &links)?;
            if let Some(missing) = selection.iter().find(|path| !files.contains_key(*path)) {
                return Err(format!("selected PBS regular file {missing:?} is absent"));
            }
            return Ok(SelectedInventory { inventory, files });
        }

        headers = headers.checked_add(1).ok_or("tar header count overflow")?;
        if headers > limits.max_entries {
            return Err("tar exceeds the header count limit".into());
        }
        validate_checksum(&header)?;
        let is_ustar = &header[257..263] == b"ustar\0" && &header[263..265] == b"00";
        let is_gnu = &header[257..265] == b"ustar  \0";
        if !is_ustar && !is_gnu {
            return Err("tar header is not supported USTAR or GNU format".into());
        }
        let size = octal(&header[124..136], "member size")?;
        let mode = u32::try_from(octal(&header[100..108], "member mode")?)
            .map_err(|_| "tar member mode exceeds u32")?;
        let entry_type = header[156];

        if matches!(entry_type, b'L' | b'K' | b'x') {
            if size > MAX_EXTENSION_BYTES {
                return Err("tar extension exceeds the 16 KiB limit".into());
            }
            let mut bytes = vec![0; usize::try_from(size).map_err(|_| "extension too large")?];
            reader.exact(&mut bytes, "tar extension payload")?;
            reader.padding(size)?;
            pending.present = true;
            match entry_type {
                b'L' => pending.set_long_path(long_value(&bytes)?)?,
                b'K' => pending.set_long_link(long_value(&bytes)?)?,
                b'x' => pending.set_pax(&bytes)?,
                _ => unreachable!(),
            }
            continue;
        }

        let kind = match entry_type {
            0 | b'0' => EntryKind::RegularFile,
            b'5' => EntryKind::Directory,
            b'2' => EntryKind::Symlink,
            b'1' => EntryKind::Hardlink,
            _ => return Err(format!("unsupported tar member type {entry_type:#04x}")),
        };
        if kind != EntryKind::RegularFile && size != 0 {
            return Err("non-regular tar member has a payload".into());
        }
        if size > limits.max_member_bytes {
            return Err("tar member exceeds the size limit".into());
        }
        total = total.checked_add(size).ok_or("tar payload size overflow")?;
        if total > limits.max_total_bytes {
            return Err("tar exceeds the total payload limit".into());
        }

        let raw_path = match pending.take_path()? {
            Some(path) => path,
            None => header_path(&header, is_ustar)?,
        };
        let path = member_path(&raw_path, kind == EntryKind::Directory)?;
        validate_insertion(&inventory.entries, &path, kind)?;
        let capture_selected = selection.contains(&path);
        if capture_selected && kind != EntryKind::RegularFile {
            return Err(format!(
                "selected PBS member {path:?} is not a regular file"
            ));
        }
        let mut entry = Entry {
            kind,
            size,
            mode,
            sha256: None,
            link_target: None,
            resolved_target: None,
        };

        if matches!(kind, EntryKind::Symlink | EntryKind::Hardlink) {
            let target = match pending.take_link()? {
                Some(target) => target,
                None => text_field(&header[157..257], "link target")?.to_owned(),
            };
            match kind {
                EntryKind::Symlink => validate_symlink_target(&target)?,
                EntryKind::Hardlink => {
                    member_path(&target, false)?;
                }
                _ => unreachable!(),
            }
            links.insert(path.clone());
            entry.link_target = Some(target);
        } else if pending.has_link() {
            return Err("tar link extension describes a non-link member".into());
        }
        pending = Extensions::default();

        if kind == EntryKind::RegularFile {
            let mut selected = if capture_selected {
                selected_bytes = selected_bytes
                    .checked_add(size)
                    .ok_or("selected PBS payload size overflow")?;
                if selected_bytes > max_selected_bytes {
                    return Err("selected PBS payloads exceed their combined size bound".into());
                }
                let mut selected = Vec::new();
                selected
                    .try_reserve_exact(
                        usize::try_from(size)
                            .map_err(|_| "selected PBS member cannot fit in memory")?,
                    )
                    .map_err(|error| format!("reserve selected PBS member: {error}"))?;
                Some(selected)
            } else {
                None
            };
            let capture_metadata = path == "python/PYTHON.json";
            if capture_metadata && size > limits.max_metadata_bytes {
                return Err("PYTHON.json exceeds the metadata size limit".into());
            }
            let mut metadata = if capture_metadata {
                Some(Vec::new())
            } else {
                None
            };
            let mut prefix = Vec::with_capacity(64);
            let mut hasher = Sha256::new();
            let mut remaining = size;
            let mut buffer = [0u8; 64 * 1024];
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                reader.exact(&mut buffer[..count], "tar member payload")?;
                hasher.update(&buffer[..count]);
                let prefix_count = count.min(64 - prefix.len());
                prefix.extend_from_slice(&buffer[..prefix_count]);
                if let Some(metadata) = metadata.as_mut() {
                    metadata.extend_from_slice(&buffer[..count]);
                }
                if let Some(selected) = selected.as_mut() {
                    selected.extend_from_slice(&buffer[..count]);
                }
                remaining -= count as u64;
            }
            let mut digest = String::with_capacity(64);
            for byte in hasher.finalize() {
                write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
            }
            entry.sha256 = Some(digest);
            if binary_magic(&prefix) {
                inventory.binary_prefixes.insert(path.clone(), prefix);
            }
            if capture_metadata {
                inventory.metadata = metadata;
            }
            if let Some(selected) = selected {
                files.insert(path.clone(), selected);
            }
        }
        reader.padding(size)?;
        inventory.entries.insert(path, entry);
    }
}

struct BoundedReader<R> {
    reader: R,
    consumed: u64,
    limit: u64,
}

impl<R: Read> BoundedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, String> {
        // One extra byte is read at the boundary to distinguish exact EOF from
        // a stream exceeding its declared bound, without unbounded buffering.
        let permitted = self.limit.saturating_sub(self.consumed).saturating_add(1);
        let count = usize::try_from(permitted.min(bytes.len() as u64))
            .map_err(|_| "tar read size overflow")?;
        let read = loop {
            match self.reader.read(&mut bytes[..count]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result.map_err(|error| format!("reading tar stream: {error}"))?,
            }
        };
        self.consumed = self
            .consumed
            .checked_add(read as u64)
            .ok_or("tar size overflow")?;
        if self.consumed > self.limit {
            return Err("tar exceeds the decompressed byte limit".into());
        }
        Ok(read)
    }

    fn exact(&mut self, mut bytes: &mut [u8], description: &str) -> Result<(), String> {
        while !bytes.is_empty() {
            let read = self.read(bytes)?;
            if read == 0 {
                return Err(format!("truncated {description}"));
            }
            bytes = &mut bytes[read..];
        }
        Ok(())
    }

    fn padding(&mut self, size: u64) -> Result<(), String> {
        let padding =
            ((BLOCK_BYTES as u64 - size % BLOCK_BYTES as u64) % BLOCK_BYTES as u64) as usize;
        let mut bytes = [0u8; BLOCK_BYTES];
        self.exact(&mut bytes[..padding], "tar member padding")?;
        if bytes[..padding].iter().any(|byte| *byte != 0) {
            return Err("nonzero tar member padding".into());
        }
        Ok(())
    }

    fn finish_padding(&mut self) -> Result<(), String> {
        let mut bytes = [0u8; 64 * 1024];
        loop {
            let count = self.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            if bytes[..count].iter().any(|byte| *byte != 0) {
                return Err("nonzero data follows the tar end markers".into());
            }
        }
        if self.consumed % BLOCK_BYTES as u64 != 0 {
            return Err("tar end padding is not a multiple of 512 bytes".into());
        }
        Ok(())
    }
}

fn validate_checksum(header: &[u8; BLOCK_BYTES]) -> Result<(), String> {
    let expected = octal(&header[148..156], "header checksum")?;
    let actual = header[..148]
        .iter()
        .chain(&header[156..])
        .map(|byte| u64::from(*byte))
        .sum::<u64>()
        + 8 * u64::from(b' ');
    if expected != actual {
        return Err("tar header checksum mismatch".into());
    }
    Ok(())
}

fn octal(field: &[u8], name: &str) -> Result<u64, String> {
    let start = field.iter().position(|byte| !matches!(byte, 0 | b' '));
    let Some(start) = start else { return Ok(0) };
    let end = field
        .iter()
        .rposition(|byte| !matches!(byte, 0 | b' '))
        .unwrap()
        + 1;
    let mut value = 0u64;
    for byte in &field[start..end] {
        if !matches!(byte, b'0'..=b'7') {
            return Err(format!("tar {name} is not an unsigned octal number"));
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| format!("tar {name} overflows u64"))?;
    }
    Ok(value)
}

fn text_field<'a>(field: &'a [u8], name: &str) -> Result<&'a str, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    // A stock PBS install-only transformation reuses the source tar header and
    // can leave old bytes after the new first NUL. These are fixed-width C
    // fields: only bytes before the first NUL participate in the path.
    std::str::from_utf8(&field[..end]).map_err(|_| format!("tar {name} is not UTF-8"))
}

fn header_path(header: &[u8; BLOCK_BYTES], is_ustar: bool) -> Result<String, String> {
    let name = text_field(&header[..100], "member path")?;
    if is_ustar {
        let prefix = text_field(&header[345..500], "member prefix")?;
        if !prefix.is_empty() {
            return Ok(format!("{prefix}/{name}"));
        }
    }
    Ok(name.to_owned())
}

fn member_path(path: &str, directory: bool) -> Result<String, String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains(['\\', '\0']) {
        return Err(
            "tar member path is empty, oversized, or contains a forbidden character".into(),
        );
    }
    let path = if directory {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    if path.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return Err("tar member path is not canonical".into());
    }
    if path.split('/').count() > MAX_PATH_COMPONENTS {
        return Err("tar member path exceeds the depth limit".into());
    }
    if path != "python" && !path.starts_with("python/") {
        return Err("tar member path is outside python/".into());
    }
    if path == "python" && !directory {
        return Err("python tar root must be a directory".into());
    }
    Ok(path.to_owned())
}

fn validate_symlink_target(target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.len() > MAX_PATH_BYTES
        || target.starts_with('/')
        || target.contains(['\\', '\0'])
    {
        return Err(
            "tar symlink target is empty, oversized, absolute, or contains a forbidden character"
                .into(),
        );
    }
    if target.split('/').any(str::is_empty) {
        return Err("tar symlink target contains an empty component".into());
    }
    if target.split('/').count() > MAX_PATH_COMPONENTS {
        return Err("tar symlink target exceeds the path depth limit".into());
    }
    // '.' and '..' must be evaluated after any directory symlink preceding
    // them, so root containment is checked by the component resolver below.
    Ok(())
}

fn validate_insertion(
    entries: &BTreeMap<String, Entry>,
    path: &str,
    kind: EntryKind,
) -> Result<(), String> {
    if entries.contains_key(path) {
        return Err(format!("duplicate tar member {path:?}"));
    }
    for (offset, _) in path.match_indices('/') {
        if let Some(ancestor) = entries.get(&path[..offset]) {
            if ancestor.kind != EntryKind::Directory {
                return Err(format!("tar member {path:?} has a non-directory ancestor"));
            }
        }
    }
    if kind != EntryKind::Directory {
        let prefix = format!("{path}/");
        if entries
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(next, _)| next.starts_with(&prefix))
        {
            return Err(format!("tar member {path:?} replaces a directory ancestor"));
        }
    }
    Ok(())
}

fn resolve_links(
    entries: &mut BTreeMap<String, Entry>,
    links: &BTreeSet<String>,
) -> Result<(), String> {
    enum Step {
        Component(String),
        EndLink(String),
    }

    fn expand(
        entries: &BTreeMap<String, Entry>,
        source: &str,
        steps: &mut VecDeque<Step>,
    ) -> Vec<String> {
        let entry = &entries[source];
        steps.push_front(Step::EndLink(source.to_owned()));
        for component in entry.link_target.as_ref().unwrap().split('/').rev() {
            steps.push_front(Step::Component(component.to_owned()));
        }
        if entry.kind == EntryKind::Symlink {
            source
                .rsplit_once('/')
                .unwrap()
                .0
                .split('/')
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        }
    }

    let mut rewrites = 0usize;
    let rewrite_limit = entries.len().saturating_mul(16).max(16);
    for source in links {
        if entries[source].resolved_target.is_some() {
            continue;
        }
        let mut steps = VecDeque::new();
        let mut components = expand(entries, source, &mut steps);
        let mut active = BTreeSet::from([source.clone()]);
        while let Some(step) = steps.pop_front() {
            match step {
                Step::EndLink(link) => {
                    let target = components.join("/");
                    let terminal_kind = entries
                        .get(&target)
                        .map(|entry| entry.kind)
                        .or_else(|| {
                            implicit_directory(entries, &target).then_some(EntryKind::Directory)
                        })
                        .ok_or_else(|| format!("dangling tar link {link:?} -> {target:?}"))?;
                    if entries[&link].kind == EntryKind::Hardlink
                        && terminal_kind != EntryKind::RegularFile
                    {
                        return Err("tar hardlink does not resolve to a regular file".into());
                    }
                    entries.get_mut(&link).unwrap().resolved_target = Some(target);
                    active.remove(&link);
                }
                Step::Component(component) => {
                    let parent = components.join("/");
                    if !components.is_empty()
                        && !entries
                            .get(&parent)
                            .is_some_and(|entry| entry.kind == EntryKind::Directory)
                        && !implicit_directory(entries, &parent)
                    {
                        return Err(format!(
                            "tar link {source:?} traverses a non-directory {parent:?}"
                        ));
                    }
                    match component.as_str() {
                        "." => continue,
                        ".." if components.len() > 1 => {
                            components.pop();
                            continue;
                        }
                        ".." => {
                            return Err(
                                "tar symlink target escapes python/ through a directory alias"
                                    .into(),
                            );
                        }
                        _ => components.push(component),
                    }
                    if components.len() > MAX_PATH_COMPONENTS {
                        return Err("resolved tar link exceeds the path depth limit".into());
                    }
                    let path = components.join("/");
                    if path.len() > MAX_PATH_BYTES {
                        return Err("resolved tar link exceeds the path limit".into());
                    }
                    if !links.contains(&path) {
                        continue;
                    }
                    rewrites = rewrites
                        .checked_add(1)
                        .ok_or("tar link rewrite count overflow")?;
                    if rewrites > rewrite_limit {
                        return Err("tar link resolution exceeds its work limit".into());
                    }
                    if !active.insert(path.clone()) {
                        return Err(format!("tar link cycle involving {path:?}"));
                    }
                    if active.len() > MAX_LINK_DEPTH {
                        return Err("tar link resolution exceeds the expansion depth limit".into());
                    }
                    if let Some(resolved) = &entries[&path].resolved_target {
                        components = resolved.split('/').map(str::to_owned).collect();
                        active.remove(&path);
                    } else {
                        components = expand(entries, &path, &mut steps);
                    }
                }
            }
        }
    }
    Ok(())
}

fn implicit_directory(entries: &BTreeMap<String, Entry>, path: &str) -> bool {
    let prefix = format!("{path}/");
    entries
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(next, _)| next.starts_with(&prefix))
}

#[derive(Default)]
struct Extensions {
    present: bool,
    long_path: Option<String>,
    long_link: Option<String>,
    pax_path: Option<String>,
    pax_link: Option<String>,
    has_pax: bool,
}

impl Extensions {
    fn set_long_path(&mut self, value: String) -> Result<(), String> {
        if self.long_path.replace(value).is_some() {
            return Err("duplicate GNU long path extension".into());
        }
        Ok(())
    }

    fn set_long_link(&mut self, value: String) -> Result<(), String> {
        if self.long_link.replace(value).is_some() {
            return Err("duplicate GNU long link extension".into());
        }
        Ok(())
    }

    fn set_pax(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.has_pax {
            return Err("duplicate local PAX extension".into());
        }
        self.has_pax = true;
        let mut seen = BTreeSet::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let length_end = bytes[offset..]
                .iter()
                .position(|byte| *byte == b' ')
                .map(|relative| offset + relative)
                .ok_or("malformed PAX record length")?;
            let length_bytes = &bytes[offset..length_end];
            if length_bytes.is_empty() || length_bytes.iter().any(|byte| !byte.is_ascii_digit()) {
                return Err("malformed PAX record length".into());
            }
            let length = std::str::from_utf8(length_bytes)
                .unwrap()
                .parse::<usize>()
                .map_err(|_| "PAX record length overflow")?;
            let end = offset
                .checked_add(length)
                .ok_or("PAX record length overflow")?;
            if end > bytes.len() || end <= length_end + 1 || bytes[end - 1] != b'\n' {
                return Err("malformed PAX record boundary".into());
            }
            let record = std::str::from_utf8(&bytes[length_end + 1..end - 1])
                .map_err(|_| "PAX record is not UTF-8")?;
            let (key, value) = record
                .split_once('=')
                .ok_or("PAX record has no assignment")?;
            if !seen.insert(key) || value.contains('\0') {
                return Err("duplicate PAX key or NUL value".into());
            }
            match key {
                "path" => self.pax_path = Some(value.to_owned()),
                "linkpath" => self.pax_link = Some(value.to_owned()),
                "mtime" | "atime" | "ctime" => validate_timestamp(value)?,
                _ => return Err(format!("unsupported PAX key {key:?}")),
            }
            offset = end;
        }
        Ok(())
    }

    fn take_path(&mut self) -> Result<Option<String>, String> {
        if self.long_path.is_some() && self.pax_path.is_some() {
            return Err("GNU and PAX path extensions describe the same member".into());
        }
        Ok(self.pax_path.take().or_else(|| self.long_path.take()))
    }

    fn take_link(&mut self) -> Result<Option<String>, String> {
        if self.long_link.is_some() && self.pax_link.is_some() {
            return Err("GNU and PAX link extensions describe the same member".into());
        }
        Ok(self.pax_link.take().or_else(|| self.long_link.take()))
    }

    fn has_link(&self) -> bool {
        self.long_link.is_some() || self.pax_link.is_some()
    }
}

fn long_value(bytes: &[u8]) -> Result<String, String> {
    let Some((&0, value)) = bytes.split_last() else {
        return Err("GNU long value has no NUL terminator".into());
    };
    if value.contains(&0) {
        return Err("GNU long value contains an embedded NUL".into());
    }
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| "GNU long value is not UTF-8".into())
}

fn validate_timestamp(value: &str) -> Result<(), String> {
    let value = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = value
        .split_once('.')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    if integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|fraction| {
            fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("PAX timestamp is not a decimal number".into());
    }
    Ok(())
}

fn binary_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(b"\x7fELF")
        || prefix.starts_with(b"MZ")
        || [
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        ]
        .iter()
        .any(|magic| prefix.starts_with(*magic))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &[u8], kind: u8, size: u64, link: &[u8]) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name);
        header[100..108].copy_from_slice(b"0000755\0");
        let size = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum(&mut header);
        header
    }

    fn checksum(header: &mut [u8; 512]) {
        header[148..156].fill(b' ');
        let sum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    fn append(bytes: &mut Vec<u8>, path: &str, kind: u8, data: &[u8], link: &str) {
        bytes.extend_from_slice(&header(
            path.as_bytes(),
            kind,
            data.len() as u64,
            link.as_bytes(),
        ));
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }

    fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend_from_slice(&[0; 1024]);
        bytes
    }

    fn read(bytes: &[u8]) -> Result<Inventory, String> {
        read_inventory(bytes, &Limits::default())
    }

    fn pax(key: &str, value: &str) -> Vec<u8> {
        let record = format!(" {key}={value}\n");
        let mut length = record.len() + 1;
        loop {
            let text = format!("{length}{record}");
            if text.len() == length {
                return text.into_bytes();
            }
            length = text.len();
        }
    }

    #[test]
    fn hashes_files_captures_only_metadata_and_binary_prefixes() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/", b'5', b"", "");
        append(&mut bytes, "python/PYTHON.json", b'0', b"{}", "");
        append(
            &mut bytes,
            "python/install/lib/python.py",
            b'0',
            b"print('hello')",
            "",
        );
        let mut binary = vec![0x55; 200];
        binary[..4].copy_from_slice(b"\x7fELF");
        append(
            &mut bytes,
            "python/install/lib/libpython.so",
            b'0',
            &binary,
            "",
        );
        let bytes = finish(bytes);
        let inventory = read(&bytes).unwrap();
        assert_eq!(inventory.decompressed_bytes, bytes.len() as u64);
        assert_eq!(inventory.metadata.as_deref(), Some(b"{}".as_slice()));
        assert_eq!(inventory.entries["python"].kind, EntryKind::Directory);
        assert_eq!(inventory.entries["python/PYTHON.json"].size, 2);
        assert_eq!(
            inventory.entries["python/PYTHON.json"].sha256.as_deref(),
            Some("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        );
        assert_eq!(inventory.binary_prefixes.len(), 1);
        assert_eq!(
            inventory.binary_prefixes["python/install/lib/libpython.so"],
            binary[..64]
        );
        assert_eq!(inventory.entries.keys().next().unwrap(), "python");
    }

    #[test]
    fn selected_payloads_preserve_the_complete_inventory() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/PYTHON.json", b'0', b"{}", "");
        append(&mut bytes, "python/runtime", b'0', b"\x7fELFlibrary", "");
        append(&mut bytes, "python/source.py", b'0', b"source", "");
        append(&mut bytes, "python/empty", b'0', b"", "");
        let bytes = finish(bytes);
        let selection = ["python/runtime", "python/empty"].map(str::to_owned).into();
        let selected = read_selected(bytes.as_slice(), &Limits::default(), &selection, 11).unwrap();
        assert_eq!(selected.inventory, read(&bytes).unwrap());
        assert_eq!(selected.files.len(), 2);
        assert_eq!(selected.files["python/runtime"], b"\x7fELFlibrary");
        assert!(selected.files["python/empty"].is_empty());
        assert!(!selected.files.contains_key("python/source.py"));
        assert!(!selected.files.contains_key("python/PYTHON.json"));
        let empty =
            read_selected(bytes.as_slice(), &Limits::default(), &BTreeSet::new(), 0).unwrap();
        assert!(empty.files.is_empty());
        assert_eq!(empty.inventory, selected.inventory);
    }

    #[test]
    fn selection_captures_metadata_only_when_explicitly_requested() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/PYTHON.json", b'0', b"{}", "");
        let selected = read_selected(
            finish(bytes).as_slice(),
            &Limits::default(),
            &BTreeSet::from(["python/PYTHON.json".into()]),
            2,
        )
        .unwrap();
        assert_eq!(selected.files["python/PYTHON.json"], b"{}");
        assert_eq!(
            selected.inventory.metadata.as_deref(),
            Some(b"{}".as_slice())
        );
    }

    #[test]
    fn selection_rejects_absent_members_directories_and_file_aliases() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/directory/", b'5', b"", "");
        append(&mut bytes, "python/file", b'0', b"payload", "");
        append(&mut bytes, "python/symlink", b'2', b"", "file");
        append(&mut bytes, "python/hardlink", b'1', b"", "python/file");
        let bytes = finish(bytes);
        for path in ["python/directory", "python/symlink", "python/hardlink"] {
            let error = read_selected(
                bytes.as_slice(),
                &Limits::default(),
                &BTreeSet::from([path.into()]),
                128,
            )
            .unwrap_err();
            assert!(error.contains("not a regular file"), "{error}");
        }
        assert!(
            read_selected(
                bytes.as_slice(),
                &Limits::default(),
                &BTreeSet::from(["python/missing".into()]),
                128
            )
            .unwrap_err()
            .contains("absent")
        );
        assert_eq!(
            read_selected(
                bytes.as_slice(),
                &Limits::default(),
                &BTreeSet::from(["python/file".into()]),
                7
            )
            .unwrap()
            .files["python/file"],
            b"payload"
        );
    }

    #[test]
    fn selection_requires_canonical_regular_file_names() {
        let bytes = finish(Vec::new());
        for path in [
            "python",
            "python/file/",
            "/python/file",
            "python/../file",
            "python/./file",
            "python\\file",
        ] {
            assert!(
                read_selected(
                    bytes.as_slice(),
                    &Limits::default(),
                    &BTreeSet::from([path.into()]),
                    128
                )
                .is_err(),
                "accepted {path:?}"
            );
        }
        let limits = Limits {
            max_entries: 0,
            ..Limits::default()
        };
        assert!(
            read_selected(
                bytes.as_slice(),
                &limits,
                &BTreeSet::from(["python/file".into()]),
                128
            )
            .unwrap_err()
            .contains("member count")
        );
    }

    #[test]
    fn selected_size_bounds_apply_before_payload_allocation_or_reading() {
        let bytes = header(b"python/file", b'0', 10, b"");
        let selection = BTreeSet::from(["python/file".into()]);
        assert!(
            read_selected(bytes.as_slice(), &Limits::default(), &selection, 9)
                .unwrap_err()
                .contains("combined size bound")
        );
        let limits = Limits {
            max_member_bytes: 9,
            ..Limits::default()
        };
        assert!(
            read_selected(bytes.as_slice(), &limits, &selection, 10)
                .unwrap_err()
                .contains("member exceeds")
        );
        assert!(
            read_selected(
                [0u8; 1024].as_slice(),
                &Limits::default(),
                &BTreeSet::new(),
                MAX_SELECTED_BYTES + 1
            )
            .unwrap_err()
            .contains("128 MiB")
        );
        let mut bytes = Vec::new();
        append(&mut bytes, "python/a", b'0', b"abc", "");
        append(&mut bytes, "python/b", b'0', b"abc", "");
        assert!(
            read_selected(
                finish(bytes).as_slice(),
                &Limits::default(),
                &BTreeSet::from(["python/a".into(), "python/b".into()]),
                5
            )
            .unwrap_err()
            .contains("combined size bound")
        );
    }

    #[test]
    fn selected_payloads_are_not_returned_before_the_rest_of_tar_validates() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/file", b'0', b"payload", "");
        let mut bad_header = header(b"python/unselected", b'0', 0, b"");
        bad_header[0] ^= 1;
        bytes.extend_from_slice(&bad_header);
        assert!(
            read_selected(
                finish(bytes).as_slice(),
                &Limits::default(),
                &BTreeSet::from(["python/file".into()]),
                7
            )
            .unwrap_err()
            .contains("checksum")
        );
        let mut bytes = Vec::new();
        append(&mut bytes, "python/file", b'0', b"payload", "");
        let mut bytes = finish(bytes);
        bytes.extend_from_slice(&header(b"python/hidden", b'0', 0, b""));
        assert!(
            read_selected(
                bytes.as_slice(),
                &Limits::default(),
                &BTreeSet::from(["python/file".into()]),
                7
            )
            .unwrap_err()
            .contains("follows")
        );
    }

    #[test]
    fn resolves_forward_symlink_and_hardlink_chains() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/", b'5', b"", "");
        append(&mut bytes, "python/install/", b'5', b"", "");
        append(&mut bytes, "python/install/bin/", b'5', b"", "");
        append(
            &mut bytes,
            "python/install/bin/python",
            b'2',
            b"",
            "./python3",
        );
        append(
            &mut bytes,
            "python/install/bin/python3",
            b'1',
            b"",
            "python/install/bin/python3.12",
        );
        append(
            &mut bytes,
            "python/install/bin/python3.12",
            b'0',
            b"MZexecutable",
            "",
        );
        let inventory = read(&finish(bytes)).unwrap();
        for path in ["python/install/bin/python", "python/install/bin/python3"] {
            assert_eq!(
                inventory.entries[path].resolved_target.as_deref(),
                Some("python/install/bin/python3.12")
            );
        }
    }

    #[test]
    fn resolves_safe_directory_alias_in_link_target() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/", b'5', b"", "");
        append(&mut bytes, "python/lib/", b'5', b"", "");
        append(&mut bytes, "python/lib/file", b'0', b"payload", "");
        append(&mut bytes, "python/lib64", b'2', b"", "lib");
        append(&mut bytes, "python/file", b'2', b"", "lib64/file");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/file"].resolved_target.as_deref(),
            Some("python/lib/file")
        );
    }

    #[test]
    fn resolves_directory_aliases_proven_by_implicit_directories() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/lib/file", b'0', b"payload", "");
        append(&mut bytes, "python/lib64", b'2', b"", "lib");
        append(&mut bytes, "python/file", b'2', b"", "lib64/file");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/lib64"].resolved_target.as_deref(),
            Some("python/lib")
        );
        assert_eq!(
            inventory.entries["python/file"].resolved_target.as_deref(),
            Some("python/lib/file")
        );
        assert!(!inventory.entries.contains_key("python/lib"));
    }

    #[test]
    fn resolves_dotdot_after_directory_aliases_in_traversal_order() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/real/deep/file", b'0', b"deep", "");
        append(&mut bytes, "python/real/wanted", b'0', b"correct", "");
        append(&mut bytes, "python/wanted", b'0', b"lexical decoy", "");
        append(&mut bytes, "python/alias", b'2', b"", "real/deep");
        append(&mut bytes, "python/link", b'2', b"", "alias/../wanted");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/link"].resolved_target.as_deref(),
            Some("python/real/wanted")
        );
    }

    #[test]
    fn permits_two_parents_after_alias_to_deeper_directory() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/real/deep/file", b'0', b"deep", "");
        append(&mut bytes, "python/wanted", b'0', b"payload", "");
        append(&mut bytes, "python/alias", b'2', b"", "real/deep");
        append(&mut bytes, "python/link", b'2', b"", "alias/../../wanted");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/link"].resolved_target.as_deref(),
            Some("python/wanted")
        );
    }

    #[test]
    fn rejects_dotdot_escape_hidden_by_directory_alias() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/dir/up", b'2', b"", "..");
        append(&mut bytes, "python/dir/outside", b'0', b"lexical decoy", "");
        append(&mut bytes, "python/link", b'2', b"", "dir/up/../outside");
        assert!(
            read(&finish(bytes))
                .unwrap_err()
                .contains("directory alias")
        );
    }

    #[test]
    fn permits_repeated_safe_alias_traversal_after_dotdot() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/lib/file", b'0', b"payload", "");
        append(&mut bytes, "python/lib64", b'2', b"", "lib");
        append(&mut bytes, "python/link", b'2', b"", "lib64/../lib64/file");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/link"].resolved_target.as_deref(),
            Some("python/lib/file")
        );
    }

    #[test]
    fn bounds_path_and_link_expansion_depth() {
        let path = format!("python/{}file", "d/".repeat(128));
        assert!(member_path(&path, false).unwrap_err().contains("depth"));
        let mut bytes = Vec::new();
        for index in 0..130 {
            append(
                &mut bytes,
                &format!("python/link{index:03}"),
                b'2',
                b"",
                &format!("link{:03}", index + 1),
            );
        }
        append(&mut bytes, "python/link130", b'0', b"payload", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("depth"));
        let mut bytes = Vec::new();
        for index in 0..60 {
            append(
                &mut bytes,
                &format!("python/link{index:03}"),
                b'2',
                b"",
                &format!("link{:03}", index + 1),
            );
        }
        append(&mut bytes, "python/link060", b'0', b"payload", "");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/link000"]
                .resolved_target
                .as_deref(),
            Some("python/link060")
        );
    }

    #[test]
    fn rejects_unsafe_member_paths() {
        for path in [
            "/python/file",
            "python/../outside",
            "python/./file",
            "python//file",
            "python\\file",
            "outside/file",
            "python/file/",
        ] {
            let mut bytes = Vec::new();
            append(&mut bytes, path, b'0', b"", "");
            assert!(read(&finish(bytes)).is_err(), "accepted {path:?}");
        }
        let bytes = finish(header(b"python/non\xffutf8", b'0', 0, b"").to_vec());
        assert!(read(&bytes).unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn fixed_fields_use_first_nul_and_reject_non_utf8_before_it() {
        let bytes = finish(header(b"python/link", b'2', 0, b"non\xffutf8").to_vec());
        assert!(read(&bytes).unwrap_err().contains("UTF-8"));
        let bytes = finish(header(b"python/name\0hidden", b'0', 0, b"").to_vec());
        let inventory = read(&bytes).unwrap();
        assert!(inventory.entries.contains_key("python/name"));
        assert!(!inventory.entries.contains_key("python/namehidden"));
        let bytes = finish(header(b"python/bin/idle3\0n/idle3", b'0', 0, b"").to_vec());
        assert!(
            read(&bytes)
                .unwrap()
                .entries
                .contains_key("python/bin/idle3")
        );
    }

    #[test]
    fn rejects_duplicate_members_including_directory_alias_spelling() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/", b'5', b"", "");
        append(&mut bytes, "python", b'5', b"", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn rejects_non_directory_ancestors_in_either_order() {
        for reverse in [false, true] {
            let mut bytes = Vec::new();
            if reverse {
                append(&mut bytes, "python/file/child", b'0', b"", "");
            }
            append(&mut bytes, "python/file", b'0', b"", "");
            if !reverse {
                append(&mut bytes, "python/file/child", b'0', b"", "");
            }
            assert!(read(&finish(bytes)).unwrap_err().contains("ancestor"));
        }
    }

    #[test]
    fn rejects_stored_members_beneath_symlink_aliases() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/alias", b'2', b"", "lib");
        append(&mut bytes, "python/alias/hidden", b'0', b"", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("ancestor"));
    }

    #[test]
    fn rejects_absolute_and_escaping_symlinks() {
        for target in ["/etc/passwd", "../../outside", "a\\b", "", "a//b"] {
            let mut bytes = Vec::new();
            append(&mut bytes, "python/bin/link", b'2', b"", target);
            assert!(read(&finish(bytes)).is_err(), "accepted {target:?}");
        }
    }

    #[test]
    fn rejects_escaping_hardlinks() {
        for target in [
            "/python/file",
            "python/../outside",
            "../outside",
            "python/./file",
        ] {
            let mut bytes = Vec::new();
            append(&mut bytes, "python/link", b'1', b"", target);
            assert!(read(&finish(bytes)).is_err(), "accepted {target:?}");
        }
    }

    #[test]
    fn rejects_dangling_and_cyclic_links() {
        let mut dangling = Vec::new();
        append(&mut dangling, "python/link", b'2', b"", "absent");
        assert!(read(&finish(dangling)).unwrap_err().contains("dangling"));
        let mut cyclic = Vec::new();
        append(&mut cyclic, "python/a", b'2', b"", "b");
        append(&mut cyclic, "python/b", b'2', b"", "a");
        assert!(read(&finish(cyclic)).unwrap_err().contains("cycle"));
        let mut directory_cycle = Vec::new();
        append(&mut directory_cycle, "python/", b'5', b"", "");
        append(&mut directory_cycle, "python/link", b'2', b"", ".");
        append(
            &mut directory_cycle,
            "python/nested",
            b'2',
            b"",
            "link/link/file",
        );
        assert!(
            read(&finish(directory_cycle))
                .unwrap_err()
                .contains("dangling")
        );
    }

    #[test]
    fn rejects_links_traversing_files_and_hardlinks_to_directories() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/file", b'0', b"payload", "");
        append(&mut bytes, "python/link", b'2', b"", "file/child");
        assert!(read(&finish(bytes)).unwrap_err().contains("non-directory"));
        let mut bytes = Vec::new();
        append(&mut bytes, "python/", b'5', b"", "");
        append(&mut bytes, "python/link", b'1', b"", "python/directory");
        append(&mut bytes, "python/directory/", b'5', b"", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("regular file"));
    }

    #[test]
    fn rejects_device_fifo_sparse_global_pax_and_unknown_types() {
        for kind in [b'3', b'4', b'6', b'7', b'S', b'g', b'Z'] {
            let bytes = finish(header(b"python/member", kind, 0, b"").to_vec());
            assert!(
                read(&bytes)
                    .unwrap_err()
                    .contains("unsupported tar member type")
            );
        }
    }

    #[test]
    fn validates_header_checksum_and_octal_numbers() {
        let mut bad_checksum = header(b"python/file", b'0', 0, b"");
        bad_checksum[0] ^= 1;
        assert!(
            read(&finish(bad_checksum.to_vec()))
                .unwrap_err()
                .contains("checksum")
        );
        for byte in [b'9', 0x80] {
            let mut bad_size = header(b"python/file", b'0', 0, b"");
            bad_size[124] = byte;
            checksum(&mut bad_size);
            assert!(
                read(&finish(bad_size.to_vec()))
                    .unwrap_err()
                    .contains("octal")
            );
        }
    }

    #[test]
    fn rejects_truncated_headers_payloads_and_padding() {
        assert!(read(&[0; 511]).unwrap_err().contains("truncated"));
        assert!(
            read(&header(b"python/file", b'0', 20, b""))
                .unwrap_err()
                .contains("payload")
        );
        let mut bytes = header(b"python/file", b'0', 1, b"").to_vec();
        bytes.push(b'a');
        assert!(read(&bytes).unwrap_err().contains("padding"));
    }

    #[test]
    fn requires_two_end_blocks_and_rejects_concatenation_or_junk() {
        assert!(read(&[]).unwrap_err().contains("truncated"));
        assert!(read(&[0; 512]).unwrap_err().contains("second"));
        let mut one_end = vec![0; 512];
        one_end.extend_from_slice(&header(b"python/file", b'0', 0, b""));
        assert!(read(&one_end).unwrap_err().contains("two consecutive"));
        let mut bytes = finish(Vec::new());
        bytes.extend_from_slice(&header(b"python/file", b'0', 0, b""));
        assert!(read(&bytes).unwrap_err().contains("follows"));
        let mut bytes = finish(Vec::new());
        bytes.push(0);
        assert!(read(&bytes).unwrap_err().contains("multiple"));
        assert!(read(&vec![0; 2048]).is_ok());
    }

    #[test]
    fn rejects_nonzero_member_padding_and_nonregular_payloads() {
        let mut bytes = Vec::new();
        append(&mut bytes, "python/file", b'0', b"a", "");
        bytes[513] = 1;
        assert!(read(&finish(bytes)).unwrap_err().contains("padding"));
        let bytes = finish(header(b"python/", b'5', 1, b"").to_vec());
        assert!(read(&bytes).unwrap_err().contains("non-regular"));
    }

    #[test]
    fn bounds_member_total_tar_metadata_and_header_counts() {
        let bytes = finish(header(b"python/file", b'0', 10, b"").to_vec());
        let limits = Limits {
            max_member_bytes: 9,
            ..Limits::default()
        };
        assert!(
            read_inventory(bytes.as_slice(), &limits)
                .unwrap_err()
                .contains("member exceeds")
        );
        let mut bytes = Vec::new();
        append(&mut bytes, "python/a", b'0', b"abc", "");
        append(&mut bytes, "python/b", b'0', b"abc", "");
        let limits = Limits {
            max_total_bytes: 5,
            ..Limits::default()
        };
        assert!(
            read_inventory(finish(bytes).as_slice(), &limits)
                .unwrap_err()
                .contains("total payload")
        );
        let limits = Limits {
            max_tar_bytes: 1024,
            ..Limits::default()
        };
        assert!(read_inventory([0; 1024].as_slice(), &limits).is_ok());
        assert!(
            read_inventory([0; 1536].as_slice(), &limits)
                .unwrap_err()
                .contains("decompressed")
        );
        let mut bytes = Vec::new();
        append(&mut bytes, "python/PYTHON.json", b'0', b"{}", "");
        let limits = Limits {
            max_metadata_bytes: 1,
            ..Limits::default()
        };
        assert!(
            read_inventory(finish(bytes).as_slice(), &limits)
                .unwrap_err()
                .contains("metadata")
        );
        let mut bytes = Vec::new();
        append(&mut bytes, "python/a", b'0', b"", "");
        append(&mut bytes, "python/b", b'0', b"", "");
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        assert!(
            read_inventory(finish(bytes).as_slice(), &limits)
                .unwrap_err()
                .contains("header count")
        );
    }

    #[test]
    fn supports_ustar_prefix_and_gnu_long_names_and_links() {
        let mut prefixed = header(b"file", b'0', 0, b"");
        prefixed[345..356].copy_from_slice(b"python/nest");
        checksum(&mut prefixed);
        assert!(
            read(&finish(prefixed.to_vec()))
                .unwrap()
                .entries
                .contains_key("python/nest/file")
        );
        let path = format!("python/{}", "a".repeat(120));
        let mut bytes = Vec::new();
        append(
            &mut bytes,
            "././@LongLink",
            b'L',
            format!("{path}\0").as_bytes(),
            "",
        );
        append(&mut bytes, "placeholder", b'0', b"data", "");
        append(
            &mut bytes,
            "././@LongLink",
            b'K',
            format!("{path}\0").as_bytes(),
            "",
        );
        append(&mut bytes, "python/link", b'1', b"", "placeholder");
        let inventory = read(&finish(bytes)).unwrap();
        assert!(inventory.entries.contains_key(&path));
        assert_eq!(
            inventory.entries["python/link"].resolved_target.as_ref(),
            Some(&path)
        );
    }

    #[test]
    fn supports_bounded_local_pax_paths_links_and_timestamps() {
        let mut bytes = Vec::new();
        let mut fields = pax("path", "python/file");
        fields.extend_from_slice(&pax("mtime", "-123.456"));
        append(&mut bytes, "PaxHeader", b'x', &fields, "");
        append(&mut bytes, "placeholder", b'0', b"data", "");
        append(&mut bytes, "PaxHeader", b'x', &pax("linkpath", "file"), "");
        append(&mut bytes, "python/link", b'2', b"", "placeholder");
        let inventory = read(&finish(bytes)).unwrap();
        assert_eq!(
            inventory.entries["python/link"].resolved_target.as_deref(),
            Some("python/file")
        );
    }

    #[test]
    fn rejects_pax_size_sparse_unknown_keys_duplicate_keys_and_bad_records() {
        for fields in [
            pax("size", "999999999999"),
            pax("GNU.sparse.map", "0,1"),
            pax("unknown", "value"),
            pax("mtime", "nan"),
            b"999 path=python/file\n".to_vec(),
            b"0 path=x\n".to_vec(),
        ] {
            let mut bytes = Vec::new();
            append(&mut bytes, "PaxHeader", b'x', &fields, "");
            append(&mut bytes, "python/file", b'0', b"", "");
            assert!(read(&finish(bytes)).is_err());
        }
        let mut fields = pax("path", "python/file");
        fields.extend_from_slice(&pax("path", "python/other"));
        let mut bytes = Vec::new();
        append(&mut bytes, "PaxHeader", b'x', &fields, "");
        assert!(read(&finish(bytes)).unwrap_err().contains("duplicate PAX"));
    }

    #[test]
    fn bounds_extensions_before_allocating_and_counts_extension_headers() {
        let bytes = finish(header(b"././@LongLink", b'L', 16 * 1024 + 1, b"").to_vec());
        assert!(read(&bytes).unwrap_err().contains("16 KiB"));
        let mut bytes = Vec::new();
        append(&mut bytes, "././@LongLink", b'L', b"python/file\0", "");
        append(&mut bytes, "placeholder", b'0', b"", "");
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        assert!(
            read_inventory(finish(bytes).as_slice(), &limits)
                .unwrap_err()
                .contains("header count")
        );
    }

    #[test]
    fn rejects_orphan_duplicate_and_conflicting_extensions() {
        let mut bytes = Vec::new();
        append(&mut bytes, "././@LongLink", b'L', b"python/file\0", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("no following"));
        let mut bytes = Vec::new();
        append(&mut bytes, "././@LongLink", b'L', b"python/file\0", "");
        append(&mut bytes, "././@LongLink", b'L', b"python/other\0", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("duplicate GNU"));
        let mut bytes = Vec::new();
        append(&mut bytes, "././@LongLink", b'L', b"python/file\0", "");
        append(
            &mut bytes,
            "PaxHeader",
            b'x',
            &pax("path", "python/file"),
            "",
        );
        append(&mut bytes, "placeholder", b'0', b"", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("GNU and PAX"));
        let mut bytes = Vec::new();
        append(&mut bytes, "././@LongLink", b'K', b"target\0", "");
        append(&mut bytes, "python/file", b'0', b"", "");
        assert!(read(&finish(bytes)).unwrap_err().contains("non-link"));
    }

    #[test]
    fn preserves_io_errors_and_accepts_short_reads() {
        struct ShortReads<'a>(&'a [u8]);
        impl Read for ShortReads<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let count = bytes.len().min(7).min(self.0.len());
                bytes[..count].copy_from_slice(&self.0[..count]);
                self.0 = &self.0[count..];
                Ok(count)
            }
        }
        let bytes = finish(Vec::new());
        assert_eq!(
            read_inventory(ShortReads(&bytes), &Limits::default())
                .unwrap()
                .decompressed_bytes,
            1024
        );
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture failure"))
            }
        }
        assert!(
            read_inventory(FailedRead, &Limits::default())
                .unwrap_err()
                .contains("fixture failure")
        );
    }
}
