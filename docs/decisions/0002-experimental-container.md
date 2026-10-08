# Experimental archive and resources (A4)

Status: accepted for schema zero, 8 October 2026. ZIP reuse remains subject to the
Node feasibility probe; this is not a frozen distribution format.

## Container layout

The separate `.glue` file is `[64-byte locator][canonical JSON manifest][ZIP]`.
The locator contains eight magic bytes (`GLUERS00`), little-endian u32 container
version (0), u32 flags (0), u64 manifest length, u64 payload length and the raw
32-byte SHA-256 manifest digest. The reader requires exact bounds and rejects
trailing bytes. ZIP offsets are relative to the payload region. Standalone
embedding/signing is separate work; this locator does not promise compatibility
with an executable certificate table or code signature.

The builder emits sorted resources, a fixed 1980 timestamp, regular Unix file
permissions and a fixed compression level. Each member is stored or deflated;
ZIP64 sizes are supported. Build-time output creation is permitted. Reading an
archive exposes bytes and metadata only and has no extraction/materialization
operation.

## Strict ZIP subset and bounds

The reader preflights the central directory and local headers before accepting
any resource. It rejects exact duplicate names, case aliases, directories,
symlinks, non-regular mode types, encryption, data descriptors, comments,
multi-disk records and unknown extra fields. Only the ZIP64 extra is admitted.
All names must match the manifest's resource inventory exactly. Local names,
methods, flags, CRCs and resolved sizes must agree with central metadata. Occupied
header/data ranges must cover the payload before the central directory without
overlap or hidden gaps. Arithmetic is checked before seeking or allocating.

The ZIP library's metadata lookup can collapse duplicates, and its normal read
API alone does not enforce this contract. Our reader owns strict metadata
validation and raw stored/deflate decoding. Decoding must reach stream end with
exact compressed-byte consumption, exact output length, CRC32 and manifest
SHA-256 agreement before publishing bytes. [ZIP library source](https://github.com/zip-rs/zip2/tree/v8.6.0/src),
[ZIP specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

Defaults bound manifest bytes (16 MiB), per-resource decoded bytes (64 MiB),
per-resource compressed input (128 MiB), summed declared payload bytes (4 GiB),
archive bytes (8 GiB), central metadata
(32 MiB) and member count (100,000). Limits are explicit and may be tightened or
raised by a trusted caller. `Archive::open` parses metadata; it does not decode
all resources. `read_resource` verifies the requested member; whole-archive
verification is explicit. These checks detect corruption, not authorship.

Resource validation also bounds path depth to 64 components, the file/directory
tree to 200,000 nodes, and the combined preserved/lowercase prefix strings to
32 MiB. These limits apply during manifest validation, before implicit directory
expansion can amplify a small JSON input into an unbounded allocation.

## Resource tree and cache

`Resources` provides read-only `stat`, `list`, `read_at` and `open` operations.
Directories are implicit and listing is deterministic. An empty path identifies
the root. Stream origins encode path characters using percent escapes so spaces,
`#` and `%` do not alias other identities when read as URLs. A requested member
is fully decoded/verified before a read-only memory
stream is returned. Stored entries also use this initial bounded memory path;
large stored resources will need a streaming verification design before enabling
cheap disk-backed positional access. No file descriptor/path materialization is
implied.

The memory cache uses an LRU policy and retains at most its configured byte
budget (default 8 MiB) and at most 4,096 entries. Empty resources and resources
larger than that byte budget are returned uncached.
Live streams and caller-owned buffers may retain verified bytes independently of
the cache; the cache budget is not a process-wide memory ceiling. The separate
per-entry decode limit bounds each operation. No user cache directory is used.

The source must remain stable while an archive is read. Holding an original
read-only file handle prevents path re-opening, but cannot prevent another process
from modifying that inode. Every returned resource is hash-verified. Worker
archive identity/lifetime handling is part of A9, not yet implemented.
