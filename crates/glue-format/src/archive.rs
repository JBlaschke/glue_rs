//! Experimental, bounded locator and stored/deflate ZIP64 resource container.
//!
//! The runtime reader never extracts files or decodes the entire payload at open.
//! Version zero intentionally accepts a canonical ZIP subset rather than general
//! ZIP compatibility: no comments, descriptors, directories, symlinks, encryption,
//! arbitrary extra fields, gaps or alternate filename encodings.

use crate::{Compression, FormatError, MAX_MANIFEST_BYTES, Manifest, ResourcePath, digest};
use flate2::{Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

pub const ARCHIVE_MAGIC: [u8; 8] = *b"GLUERS00";
pub const ARCHIVE_VERSION: u32 = 0;
pub const LOCATOR_SIZE: u64 = 64;

/// Policy limits are checked before archive-controlled allocations or decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub max_manifest_bytes: u64,
    pub max_archive_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_compressed_entry_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    pub max_central_directory_bytes: u64,
    pub max_entries: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: MAX_MANIFEST_BYTES as u64,
            max_archive_bytes: 8 * 1024 * 1024 * 1024,
            max_entry_bytes: 64 * 1024 * 1024,
            max_compressed_entry_bytes: 128 * 1024 * 1024,
            max_total_uncompressed_bytes: 4 * 1024 * 1024 * 1024,
            max_central_directory_bytes: 32 * 1024 * 1024,
            max_entries: 100_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive I/O: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Manifest(#[from] FormatError),
    #[error("invalid archive: {0}")]
    Invalid(String),
    #[error("archive exceeds {limit}: {actual} > {maximum}")]
    Limit {
        limit: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("resource {0:?} is not in the archive")]
    ResourceNotFound(String),
    #[error("resource {path:?} failed {check} verification")]
    Integrity { path: String, check: &'static str },
    #[error("ZIP writer: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("unable to allocate a bounded archive buffer")]
    Allocation,
}

/// All offsets are relative to the independently seekable ZIP payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub size: u64,
    pub compressed_size: u64,
    pub compression: Compression,
    pub crc32: u32,
    pub header_offset: u64,
    pub data_offset: u64,
}

/// Read-only archive access. A source must retain its bytes while this object is
/// in use; resource checks detect changed content before publishing decoded data.
#[derive(Debug)]
pub struct Archive<R> {
    source: R,
    manifest: Manifest,
    entries: BTreeMap<String, ArchiveEntry>,
    payload_offset: u64,
    limits: ArchiveLimits,
}

impl<R: Read + Seek> Archive<R> {
    pub fn open(source: R) -> Result<Self, ArchiveError> {
        Self::open_with_limits(source, ArchiveLimits::default())
    }

    pub fn open_with_limits(mut source: R, limits: ArchiveLimits) -> Result<Self, ArchiveError> {
        let source_len = source.seek(SeekFrom::End(0))?;
        limit("archive bytes", source_len, limits.max_archive_bytes)?;
        if source_len < LOCATOR_SIZE {
            return invalid("truncated locator");
        }
        let mut locator = [0; LOCATOR_SIZE as usize];
        source.seek(SeekFrom::Start(0))?;
        source.read_exact(&mut locator)?;
        if locator[..8] != ARCHIVE_MAGIC {
            return invalid("unrecognized locator magic");
        }
        if u32_at(&locator, 8) != ARCHIVE_VERSION || u32_at(&locator, 12) != 0 {
            return invalid("unsupported locator version or flags");
        }
        let manifest_len = u64_at(&locator, 16);
        let payload_len = u64_at(&locator, 24);
        limit("manifest bytes", manifest_len, limits.max_manifest_bytes)?;
        limit(
            "manifest schema bytes",
            manifest_len,
            MAX_MANIFEST_BYTES as u64,
        )?;
        let payload_offset = add(LOCATOR_SIZE, manifest_len)?;
        if add(payload_offset, payload_len)? != source_len {
            return invalid("locator regions do not cover the source exactly");
        }
        let mut manifest_bytes = allocated(manifest_len)?;
        source.read_exact(&mut manifest_bytes)?;
        if Sha256::digest(&manifest_bytes).as_slice() != &locator[32..64] {
            return invalid("manifest SHA-256 mismatch");
        }
        let manifest = Manifest::from_json(&manifest_bytes)?;
        if manifest.to_json()? != manifest_bytes {
            return invalid("manifest is not canonical JSON");
        }
        limit(
            "entry count",
            manifest.resources.len() as u64,
            limits.max_entries,
        )?;
        let mut total = 0;
        for resource in manifest.resources.values() {
            limit("resource bytes", resource.size, limits.max_entry_bytes)?;
            total = add(total, resource.size)?;
            limit(
                "total resource bytes",
                total,
                limits.max_total_uncompressed_bytes,
            )?;
        }
        let entries = preflight(&mut source, payload_offset, payload_len, limits)?;
        if entries.len() != manifest.resources.len() {
            return invalid("manifest and payload have different resource counts");
        }
        for (path, entry) in &entries {
            let resource = manifest.resources.get(path).ok_or_else(|| {
                ArchiveError::Invalid(format!("undeclared payload resource {path:?}"))
            })?;
            if resource.size != entry.size || resource.compression != entry.compression {
                return invalid(format!("manifest size/compression disagrees for {path:?}"));
            }
        }
        Ok(Self {
            source,
            manifest,
            entries,
            payload_offset,
            limits,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn entries(&self) -> &BTreeMap<String, ArchiveEntry> {
        &self.entries
    }

    /// Publish bytes only after exact length, CRC32 and manifest SHA-256 checks.
    pub fn read_resource(&mut self, path: &str) -> Result<Vec<u8>, ArchiveError> {
        ResourcePath::new(path)?;
        let entry = self
            .entries
            .get(path)
            .ok_or_else(|| ArchiveError::ResourceNotFound(path.to_owned()))?;
        limit("resource bytes", entry.size, self.limits.max_entry_bytes)?;
        self.source.seek(SeekFrom::Start(add(
            self.payload_offset,
            entry.data_offset,
        )?))?;
        let mut output = Vec::new();
        let size = usize::try_from(entry.size).map_err(|_| ArchiveError::Allocation)?;
        output
            .try_reserve_exact(size)
            .map_err(|_| ArchiveError::Allocation)?;
        let mut source = (&mut self.source).take(entry.compressed_size);
        let mut crc = crc32fast::Hasher::new();
        let mut sha = Sha256::new();
        let mut append = |bytes: &[u8]| -> Result<(), ArchiveError> {
            if add(output.len() as u64, bytes.len() as u64)? > entry.size {
                return integrity(path, "length");
            }
            crc.update(bytes);
            sha.update(bytes);
            output.extend_from_slice(bytes);
            Ok(())
        };
        match entry.compression {
            Compression::Stored => {
                let mut buffer = [0; 32 * 1024];
                loop {
                    let count = source.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    append(&buffer[..count])?;
                }
                if source.limit() != 0 {
                    return integrity(path, "compressed length");
                }
            }
            Compression::Deflate => {
                decode_deflate(&mut source, entry.compressed_size, path, &mut append)?;
            }
        }
        if output.len() as u64 != entry.size {
            return integrity(path, "length");
        }
        if crc.finalize() != entry.crc32 {
            return integrity(path, "CRC32");
        }
        let actual = sha.finalize();
        let expected = &self.manifest.resources[path].sha256;
        if hex_digest(actual.as_slice()) != *expected {
            return integrity(path, "SHA-256");
        }
        Ok(output)
    }

    pub fn verify_all(&mut self) -> Result<(), ArchiveError> {
        // The name list is bounded by the already validated manifest and index.
        let paths: Vec<_> = self.entries.keys().cloned().collect();
        for path in paths {
            self.read_resource(&path)?;
        }
        Ok(())
    }
}

/// Build-time writer. `writer` must be empty; generic `Write + Seek` cannot
/// truncate existing files. The current builder buffers compressed payload bytes
/// in memory so ZIP offsets remain independent of the locator and manifest.
pub fn write_archive<W: Write + Seek>(
    mut writer: W,
    manifest: &Manifest,
    resources: &BTreeMap<String, Vec<u8>>,
) -> Result<W, ArchiveError> {
    if writer.seek(SeekFrom::End(0))? != 0 {
        return invalid("archive destination must be empty");
    }
    writer.seek(SeekFrom::Start(0))?;
    let manifest_bytes = manifest.to_json()?;
    if resources.len() != manifest.resources.len() {
        return invalid("builder resources do not match manifest resource count");
    }
    for (path, bytes) in resources {
        let spec = manifest.resources.get(path).ok_or_else(|| {
            ArchiveError::Invalid(format!("undeclared builder resource {path:?}"))
        })?;
        if bytes.len() as u64 != spec.size || digest(bytes) != spec.sha256 {
            return integrity(path, "builder length/SHA-256");
        }
    }
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in resources {
        let method = match manifest.resources[path].compression {
            Compression::Stored => zip::CompressionMethod::Stored,
            Compression::Deflate => zip::CompressionMethod::Deflated,
        };
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .compression_level(if method == zip::CompressionMethod::Deflated {
                Some(6)
            } else {
                None
            })
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644)
            .system(zip::System::Unix)
            .large_file(true);
        zip.start_file(path, options)?;
        zip.write_all(bytes)?;
    }
    let payload = zip.finish()?.into_inner();
    writer.write_all(&ARCHIVE_MAGIC)?;
    writer.write_all(&ARCHIVE_VERSION.to_le_bytes())?;
    writer.write_all(&0_u32.to_le_bytes())?;
    writer.write_all(&(manifest_bytes.len() as u64).to_le_bytes())?;
    writer.write_all(&(payload.len() as u64).to_le_bytes())?;
    writer.write_all(&Sha256::digest(&manifest_bytes))?;
    writer.write_all(&manifest_bytes)?;
    writer.write_all(&payload)?;
    Ok(writer)
}

fn decode_deflate(
    source: &mut impl Read,
    compressed_size: u64,
    path: &str,
    append: &mut impl FnMut(&[u8]) -> Result<(), ArchiveError>,
) -> Result<(), ArchiveError> {
    let mut decoder = Decompress::new(false);
    let mut input = [0; 32 * 1024];
    let mut output = [0; 32 * 1024];
    let mut input_len = 0;
    let mut input_position = 0;
    let mut eof = false;
    loop {
        if input_position == input_len && !eof {
            input_len = source.read(&mut input)?;
            input_position = 0;
            eof = input_len == 0;
        }
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(
                &input[input_position..input_len],
                &mut output,
                if eof {
                    FlushDecompress::Finish
                } else {
                    FlushDecompress::None
                },
            )
            .map_err(|_| ArchiveError::Integrity {
                path: path.to_owned(),
                check: "deflate stream",
            })?;
        let consumed = (decoder.total_in() - before_in) as usize;
        let produced = (decoder.total_out() - before_out) as usize;
        input_position += consumed;
        append(&output[..produced])?;
        if status == Status::StreamEnd {
            if decoder.total_in() != compressed_size {
                return integrity(path, "compressed length");
            }
            return Ok(());
        }
        if consumed == 0 && produced == 0 {
            return integrity(path, "incomplete deflate stream");
        }
    }
}

#[derive(Debug)]
struct CentralEntry {
    path: String,
    flags: u16,
    version: u16,
    entry: ArchiveEntry,
}

fn preflight<R: Read + Seek>(
    source: &mut R,
    base: u64,
    length: u64,
    limits: ArchiveLimits,
) -> Result<BTreeMap<String, ArchiveEntry>, ArchiveError> {
    if length < 22 {
        return invalid("truncated ZIP footer");
    }
    let eocd_offset = length - 22;
    let eocd = fixed::<22>(source, base, length, eocd_offset)?;
    if u32_at(&eocd, 0) != 0x0605_4b50 || u16_at(&eocd, 20) != 0 {
        return invalid("ZIP must end with a comment-free EOCD");
    }
    if u16_at(&eocd, 4) != 0 || u16_at(&eocd, 6) != 0 {
        return invalid("multi-disk ZIP is unsupported");
    }
    let count32 = u16_at(&eocd, 10);
    if u16_at(&eocd, 8) != count32 {
        return invalid("ZIP entry counts disagree");
    }
    let size32 = u32_at(&eocd, 12);
    let offset32 = u32_at(&eocd, 16);
    let sentinel = count32 == u16::MAX || size32 == u32::MAX || offset32 == u32::MAX;
    let locator = if eocd_offset >= 20 {
        let block = fixed::<20>(source, base, length, eocd_offset - 20)?;
        (u32_at(&block, 0) == 0x0706_4b50).then_some(block)
    } else {
        None
    };
    let (count, cd_size, cd_offset, footer_offset) = if let Some(locator) = locator {
        if u32_at(&locator, 4) != 0 || u32_at(&locator, 16) != 1 {
            return invalid("invalid ZIP64 disk locator");
        }
        let offset = u64_at(&locator, 8);
        if add(offset, 56)? != eocd_offset - 20 {
            return invalid("noncanonical ZIP64 footer range");
        }
        let block = fixed::<56>(source, base, length, offset)?;
        if u32_at(&block, 0) != 0x0606_4b50 || u64_at(&block, 4) != 44 {
            return invalid("ZIP64 extensible footer data is unsupported");
        }
        if u32_at(&block, 16) != 0 || u32_at(&block, 20) != 0 {
            return invalid("multi-disk ZIP64 is unsupported");
        }
        let count = u64_at(&block, 32);
        let size = u64_at(&block, 40);
        let start = u64_at(&block, 48);
        if u64_at(&block, 24) != count
            || (count32 != u16::MAX && u64::from(count32) != count)
            || (size32 != u32::MAX && u64::from(size32) != size)
            || (offset32 != u32::MAX && u64::from(offset32) != start)
        {
            return invalid("ZIP32 and ZIP64 footer fields disagree");
        }
        (count, size, start, offset)
    } else {
        if sentinel {
            return invalid("ZIP64 footer is missing");
        }
        (
            u64::from(count32),
            u64::from(size32),
            u64::from(offset32),
            eocd_offset,
        )
    };
    limit("entry count", count, limits.max_entries)?;
    limit(
        "central directory bytes",
        cd_size,
        limits.max_central_directory_bytes,
    )?;
    if add(cd_offset, cd_size)? != footer_offset || count > cd_size / 46 {
        return invalid("invalid central directory bounds/count");
    }
    let mut position = cd_offset;
    let mut central = Vec::new();
    central
        .try_reserve_exact(usize::try_from(count).map_err(|_| ArchiveError::Allocation)?)
        .map_err(|_| ArchiveError::Allocation)?;
    let mut names = BTreeMap::new();
    let mut total = 0;
    for _ in 0..count {
        if add(position, 46)? > footer_offset {
            return invalid("truncated central entry");
        }
        let block = fixed::<46>(source, base, length, position)?;
        if u32_at(&block, 0) != 0x0201_4b50 {
            return invalid("invalid central entry signature");
        }
        let version = u16_at(&block, 6);
        let flags = u16_at(&block, 8);
        let method = u16_at(&block, 10);
        let compression = compression(method, flags, version)?;
        let name_len = u16_at(&block, 28) as u64;
        let extra_len = u16_at(&block, 30) as u64;
        if name_len == 0 || name_len > 4096 || extra_len > 32 || u16_at(&block, 32) != 0 {
            return invalid("unsupported central name, extra field or comment length");
        }
        let attributes = u32_at(&block, 38);
        let file_type = (attributes >> 16) & 0o170000;
        if attributes & 0x10 != 0 || (file_type != 0 && file_type != 0o100000) {
            return invalid("directories, symlinks and special members are unsupported");
        }
        let variable_start = add(position, 46)?;
        let end = add(variable_start, add(name_len, extra_len)?)?;
        if end > footer_offset {
            return invalid("central variable fields exceed directory");
        }
        let name = bytes(source, base, length, variable_start, name_len)?;
        let path = String::from_utf8(name)
            .map_err(|_| ArchiveError::Invalid("non-UTF8 ZIP name".to_owned()))?;
        ResourcePath::new(&path)?;
        if names.insert(path.clone(), ()).is_some() {
            return invalid("duplicate ZIP resource name");
        }
        let extra = bytes(
            source,
            base,
            length,
            add(variable_start, name_len)?,
            extra_len,
        )?;
        let (size, compressed_size, header_offset, disk) = zip64_values(
            &extra,
            u32_at(&block, 24),
            u32_at(&block, 20),
            Some(u32_at(&block, 42)),
            Some(u16_at(&block, 34)),
        )?;
        limit(
            "compressed resource bytes",
            compressed_size,
            limits.max_compressed_entry_bytes,
        )?;
        if disk != 0 {
            return invalid("member references another ZIP disk");
        }
        limit("resource bytes", size, limits.max_entry_bytes)?;
        total = add(total, size)?;
        limit(
            "total resource bytes",
            total,
            limits.max_total_uncompressed_bytes,
        )?;
        if compressed_size > length {
            return invalid("compressed member exceeds payload");
        }
        if compression == Compression::Stored && size != compressed_size {
            return invalid("stored resource lengths disagree");
        }
        central.push(CentralEntry {
            path,
            flags,
            version,
            entry: ArchiveEntry {
                size,
                compressed_size,
                compression,
                crc32: u32_at(&block, 16),
                header_offset,
                data_offset: 0,
            },
        });
        position = end;
    }
    if position != footer_offset {
        return invalid("central directory size/count does not match records");
    }
    // Manifest validation includes implicit directory and case aliases. Check the
    // ZIP names independently before trusting that the sets match.
    crate::validate_resource_paths(names.keys())?;
    let mut ranges = Vec::new();
    let mut entries = BTreeMap::new();
    for mut record in central {
        let entry = &mut record.entry;
        if add(entry.header_offset, 30)? > cd_offset {
            return invalid("local header overlaps central directory");
        }
        let block = fixed::<30>(source, base, length, entry.header_offset)?;
        if u32_at(&block, 0) != 0x0403_4b50
            || u16_at(&block, 4) != record.version
            || u16_at(&block, 6) != record.flags
            || compression(u16_at(&block, 8), u16_at(&block, 6), u16_at(&block, 4))?
                != entry.compression
            || u32_at(&block, 14) != entry.crc32
        {
            return invalid("local and central header fields disagree");
        }
        let name_len = u16_at(&block, 26) as u64;
        let extra_len = u16_at(&block, 28) as u64;
        if name_len != record.path.len() as u64 || extra_len > 32 {
            return invalid("local name/extra length mismatch");
        }
        let variable_start = add(entry.header_offset, 30)?;
        entry.data_offset = add(variable_start, add(name_len, extra_len)?)?;
        let end = add(entry.data_offset, entry.compressed_size)?;
        if end > cd_offset {
            return invalid("member range overlaps central directory");
        }
        if bytes(source, base, length, variable_start, name_len)? != record.path.as_bytes() {
            return invalid("local and central resource names disagree");
        }
        let extra = bytes(
            source,
            base,
            length,
            add(variable_start, name_len)?,
            extra_len,
        )?;
        let (size, compressed, _, _) =
            zip64_values(&extra, u32_at(&block, 22), u32_at(&block, 18), None, None)?;
        if size != entry.size || compressed != entry.compressed_size {
            return invalid("local and central resource sizes disagree");
        }
        ranges.push(entry.header_offset..end);
        entries.insert(record.path, record.entry);
    }
    ranges.sort_unstable_by_key(|range| range.start);
    let mut end = 0;
    for range in ranges {
        if range.start != end {
            return invalid("overlapping members or noncanonical payload gaps");
        }
        end = range.end;
    }
    if end != cd_offset {
        return invalid("payload contains unindexed bytes");
    }
    Ok(entries)
}

fn zip64_values(
    extra: &[u8],
    size32: u32,
    compressed32: u32,
    offset32: Option<u32>,
    disk16: Option<u16>,
) -> Result<(u64, u64, u64, u32), ArchiveError> {
    let size64 = size32 == u32::MAX;
    let compressed64 = compressed32 == u32::MAX;
    let offset64 = offset32 == Some(u32::MAX);
    let disk64 = disk16 == Some(u16::MAX);
    let expected = 8 * (usize::from(size64) + usize::from(compressed64) + usize::from(offset64))
        + 4 * usize::from(disk64);
    if expected == 0 {
        if !extra.is_empty() {
            return invalid("unexpected ZIP extra field");
        }
        return Ok((
            u64::from(size32),
            u64::from(compressed32),
            u64::from(offset32.unwrap_or(0)),
            u32::from(disk16.unwrap_or(0)),
        ));
    }
    if extra.len() != expected + 4
        || u16_at(extra, 0) != 1
        || usize::from(u16_at(extra, 2)) != expected
    {
        return invalid("missing, repeated or malformed ZIP64 extra field");
    }
    let mut position = 4;
    let mut next = || {
        let value = u64_at(extra, position);
        position += 8;
        value
    };
    let size = if size64 { next() } else { u64::from(size32) };
    let compressed = if compressed64 {
        next()
    } else {
        u64::from(compressed32)
    };
    let offset = if offset64 {
        next()
    } else {
        u64::from(offset32.unwrap_or(0))
    };
    let disk = if disk64 {
        u32_at(extra, position)
    } else {
        u32::from(disk16.unwrap_or(0))
    };
    Ok((size, compressed, offset, disk))
}

fn compression(method: u16, flags: u16, version: u16) -> Result<Compression, ArchiveError> {
    if flags & !0x0806 != 0 || !matches!(version, 10 | 20 | 45) {
        return invalid("unsupported ZIP flags/version (encryption and descriptors are forbidden)");
    }
    match method {
        0 if flags & 6 == 0 => Ok(Compression::Stored),
        8 if version >= 20 => Ok(Compression::Deflate),
        _ => invalid("unsupported ZIP compression method/flags"),
    }
}

fn fixed<const N: usize>(
    source: &mut (impl Read + Seek),
    base: u64,
    length: u64,
    position: u64,
) -> Result<[u8; N], ArchiveError> {
    if add(position, N as u64)? > length {
        return invalid("ZIP record extends past payload");
    }
    source.seek(SeekFrom::Start(add(base, position)?))?;
    let mut block = [0; N];
    source.read_exact(&mut block)?;
    Ok(block)
}

fn bytes(
    source: &mut (impl Read + Seek),
    base: u64,
    length: u64,
    position: u64,
    count: u64,
) -> Result<Vec<u8>, ArchiveError> {
    if add(position, count)? > length {
        return invalid("ZIP field extends past payload");
    }
    let mut buffer = allocated(count)?;
    source.seek(SeekFrom::Start(add(base, position)?))?;
    source.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn allocated(size: u64) -> Result<Vec<u8>, ArchiveError> {
    let size = usize::try_from(size).map_err(|_| ArchiveError::Allocation)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ArchiveError::Allocation)?;
    bytes.resize(size, 0);
    Ok(bytes)
}

fn add(left: u64, right: u64) -> Result<u64, ArchiveError> {
    left.checked_add(right)
        .ok_or_else(|| ArchiveError::Invalid("overflowing archive offset/size".to_owned()))
}
fn limit(name: &'static str, actual: u64, maximum: u64) -> Result<(), ArchiveError> {
    if actual > maximum {
        return Err(ArchiveError::Limit {
            limit: name,
            actual,
            maximum,
        });
    }
    Ok(())
}
fn invalid<T>(message: impl Into<String>) -> Result<T, ArchiveError> {
    Err(ArchiveError::Invalid(message.into()))
}
fn integrity<T>(path: &str, check: &'static str) -> Result<T, ArchiveError> {
    Err(ArchiveError::Integrity {
        path: path.to_owned(),
        check,
    })
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(64);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("String formatting cannot fail");
    }
    value
}
