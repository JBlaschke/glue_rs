//! Read-only resources inside a validated glue archive.
//!
//! Paths are canonical archive identities, never host filesystem paths. Files
//! become visible as bytes only after the archive has fully decoded their
//! payloads and verified their hashes. There is no extraction or write API.
//!
//! The cache budget bounds decompressed bytes retained by [`Resources`], and
//! [`MAX_CACHE_ENTRIES`] bounds cache bookkeeping. Empty payloads are not cached.
//! Open streams and returned [`Arc`] values can keep bytes alive after eviction
//! and are not included in that budget. Individual decodes are separately
//! bounded by the limits used to open the underlying archive.

use glue_format::{Archive, ArchiveError, Compression, FormatError, Manifest, ResourcePath};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Read, Seek, SeekFrom},
    sync::Arc,
};

/// Default retained decompressed cache size: 8 MiB.
pub const DEFAULT_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum retained cache entries, independent of the decompressed byte budget.
pub const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    InvalidPath(#[from] FormatError),
    #[error("resource does not exist: {0:?}")]
    NotFound(String),
    #[error("resource is not a directory: {0:?}")]
    NotDirectory(String),
    #[error("resource is a directory: {0:?}")]
    IsDirectory(String),
    #[error("resource offset exceeds the addressable range")]
    OffsetOverflow,
}

pub type Result<T> = std::result::Result<T, ResourceError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
}

/// Resource metadata. Implicit directories have zero sizes and no compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub kind: EntryKind,
    pub size: u64,
    pub compressed_size: u64,
    pub compression: Option<Compression>,
}

impl Metadata {
    pub fn is_file(self) -> bool {
        self.kind == EntryKind::File
    }

    pub fn is_dir(self) -> bool {
        self.kind == EntryKind::Directory
    }

    fn directory() -> Self {
        Self {
            kind: EntryKind::Directory,
            size: 0,
            compressed_size: 0,
            compression: None,
        }
    }
}

/// One immediate child of a directory, ordered lexicographically by name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub name: String,
    /// Full canonical identity relative to the archive root.
    pub path: String,
    pub metadata: Metadata,
}

/// Directory operations and verified reads over an owned archive.
///
/// The empty path identifies the root. All other paths follow
/// [`ResourcePath`]'s validation rules; aliases such as `.` or a trailing slash
/// are rejected. A zero cache budget disables caching. Empty files are never
/// cached, and the cache retains at most [`MAX_CACHE_ENTRIES`] nonempty files.
pub struct Resources<R: Read + Seek> {
    archive: Archive<R>,
    nodes: BTreeMap<String, Metadata>,
    cache: BTreeMap<String, Arc<[u8]>>,
    // Oldest entry first. Each cached path occurs exactly once.
    recency: VecDeque<String>,
    cache_budget: usize,
    cache_bytes: usize,
}

impl<R: Read + Seek> Resources<R> {
    pub fn new(archive: Archive<R>, cache_budget: usize) -> Self {
        let mut nodes = BTreeMap::from([(String::new(), Metadata::directory())]);
        for (path, spec) in &archive.manifest().resources {
            let entry = archive
                .entries()
                .get(path)
                .expect("a validated archive indexes every manifest resource");
            nodes.insert(
                path.clone(),
                Metadata {
                    kind: EntryKind::File,
                    size: spec.size,
                    compressed_size: entry.compressed_size,
                    compression: Some(spec.compression),
                },
            );
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                nodes
                    .entry(prefix.to_owned())
                    .or_insert_with(Metadata::directory);
                parent = prefix;
            }
        }
        Self {
            archive,
            nodes,
            cache: BTreeMap::new(),
            recency: VecDeque::new(),
            cache_budget,
            cache_bytes: 0,
        }
    }

    pub fn with_default_cache(archive: Archive<R>) -> Self {
        Self::new(archive, DEFAULT_CACHE_BYTES)
    }

    pub fn manifest(&self) -> &Manifest {
        self.archive.manifest()
    }

    /// Bytes retained in the cache, excluding outstanding reads and streams.
    /// Cache bookkeeping is separately bounded by [`MAX_CACHE_ENTRIES`].
    pub fn cache_bytes(&self) -> usize {
        self.cache_bytes
    }

    pub fn cache_budget(&self) -> usize {
        self.cache_budget
    }

    /// Number of retained nonempty files, never exceeding [`MAX_CACHE_ENTRIES`].
    pub fn cached_resources(&self) -> usize {
        self.cache.len()
    }

    pub fn stat(&self, path: &str) -> Result<Metadata> {
        if !path.is_empty() {
            ResourcePath::new(path)?;
        }
        self.nodes
            .get(path)
            .copied()
            .ok_or_else(|| ResourceError::NotFound(path.to_owned()))
    }

    pub fn list(&self, path: &str) -> Result<Vec<DirEntry>> {
        if !self.stat(path)?.is_dir() {
            return Err(ResourceError::NotDirectory(path.to_owned()));
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        Ok(self
            .nodes
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, metadata)| {
                let name = &key[prefix.len()..];
                (!name.is_empty() && !name.contains('/')).then(|| DirEntry {
                    name: name.to_owned(),
                    path: key.clone(),
                    metadata: *metadata,
                })
            })
            .collect())
    }

    /// Read a complete verified resource. Empty and oversized entries are
    /// returned without entering the cache; cache hits return the same immutable
    /// allocation. Admission evicts the least recently used files as needed to
    /// respect both the byte budget and [`MAX_CACHE_ENTRIES`].
    pub fn read(&mut self, path: &str) -> Result<Arc<[u8]>> {
        if self.stat(path)?.is_dir() {
            return Err(ResourceError::IsDirectory(path.to_owned()));
        }
        if let Some(bytes) = self.cache.get(path).cloned() {
            self.touch(path);
            return Ok(bytes);
        }

        // No bytes or cache changes are published before verification succeeds.
        let bytes: Arc<[u8]> = self.archive.read_resource(path)?.into();
        if !bytes.is_empty() && self.cache_budget != 0 && bytes.len() <= self.cache_budget {
            // Subtraction avoids overflowing cache_bytes + bytes.len().
            while self.cache_bytes > self.cache_budget - bytes.len()
                || self.cache.len() >= MAX_CACHE_ENTRIES
            {
                let oldest = self
                    .recency
                    .pop_front()
                    .expect("a nonempty cache has an oldest entry");
                let evicted = self
                    .cache
                    .remove(&oldest)
                    .expect("cache recency contains only cached paths");
                self.cache_bytes -= evicted.len();
            }
            self.cache_bytes += bytes.len();
            self.cache.insert(path.to_owned(), Arc::clone(&bytes));
            self.recency.push_back(path.to_owned());
        }
        Ok(bytes)
    }

    /// Read from a byte offset. At or beyond EOF this returns zero, including
    /// offsets that do not fit the host's address space.
    pub fn read_at(&mut self, path: &str, offset: u64, output: &mut [u8]) -> Result<usize> {
        let bytes = self.read(path)?;
        copy_at(&bytes, offset, output).ok_or(ResourceError::OffsetOverflow)
    }

    /// Open a seekable stream backed by a complete verified immutable payload.
    pub fn open(&mut self, path: &str) -> Result<ResourceStream> {
        let bytes = self.read(path)?;
        Ok(ResourceStream {
            bytes,
            position: 0,
            origin: format!(
                "glue://{}/{}",
                self.manifest().app_id,
                encode_origin_path(path)
            ),
        })
    }

    fn touch(&mut self, path: &str) {
        let position = self
            .recency
            .iter()
            .position(|entry| entry == path)
            .expect("each cache entry has a recency position");
        let key = self.recency.remove(position).unwrap();
        self.recency.push_back(key);
    }
}

/// A read-only stream independent of the archive and its cache lifetime.
///
/// Clones share verified bytes and have independent cursor positions. Seeking
/// beyond EOF is allowed; seeking before zero or beyond `u64::MAX` fails without
/// changing the current position. This type deliberately does not implement
/// [`io::Write`].
#[derive(Clone, Debug)]
pub struct ResourceStream {
    bytes: Arc<[u8]>,
    position: u64,
    origin: String,
}

impl ResourceStream {
    /// Archive identity suitable for diagnostics; it is not a filesystem path.
    /// Path separators are preserved and other characters outside URI
    /// unreserved ASCII are percent-encoded with uppercase hexadecimal digits.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl Read for ResourceStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = copy_at(&self.bytes, self.position, output).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "resource offset overflow")
        })?;
        self.position = self.position.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "resource offset overflow")
        })?;
        Ok(count)
    }
}

impl Seek for ResourceStream {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => (self.bytes.len() as u64).checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "resource seek out of range"))?;
        self.position = position;
        Ok(position)
    }
}

fn copy_at(bytes: &[u8], offset: u64, output: &mut [u8]) -> Option<usize> {
    let start = match usize::try_from(offset) {
        Ok(start) if start < bytes.len() => start,
        _ => return Some(0),
    };
    let count = output.len().min(bytes.len() - start);
    let end = start.checked_add(count)?;
    output[..count].copy_from_slice(&bytes[start..end]);
    Some(count)
}

fn encode_origin_path(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}
