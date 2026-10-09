# Pinned stock PBS input inspection

Status: experimental build-time implementation on
`codex/a7-pbs-artifact-inspection`, from merged `1425d6d`.

## Decision

Add `glue-pbs` and the `glue-pbs-inspect` binary as a build-time inspection
foundation for A7/A10. The tool reads already downloaded artifacts and emits
deterministic JSON to stdout. It does not download, extract, acquire a runtime,
execute Python, or produce a runnable `glue` manifest. Existing Lua execution
profiles keep their identities.

The initial inspected inputs are conventional-GIL CPython 3.13.16 from PBS
release `20261009`, source commit
`ccc07c40c2731bfb459c119f2388f65a5a470de6`, for
`aarch64-unknown-linux-gnu` with `pgo+lto`. Both full and unstripped install-only
compressed artifacts have independent size/SHA-256 pins in
[the fixture](../../fixtures/python-pbs/pins.json). The downloads were verified
against upstream `SHA256SUMS` and GitHub's asset digests. This adds an exact
build-time input pin; it does not establish an accepted Python execution profile.

## Admission and output

Check compressed identity before parsing and again against the bytes consumed
by decompression, preventing a changed input from producing a report. Accept one
Zstandard frame for full archives and one gzip member for install-only; validate
checksums and reject extra compressed frames/members or trailing bytes.
Zstandard's window is bounded to 128 MiB before allocation: this is the window
advertised by the pinned full artifact. Larger windows are unsupported.

The streaming TAR reader counts every raw header, including extension headers.
Default bounds are 512 MiB compressed input, 3 GiB expanded TAR, 2 GiB regular
payload, 256 MiB per file, 50,000 headers, 1 MiB `PYTHON.json`, 16 KiB per GNU/PAX
extension, and 4 KiB paths. It hashes and discards regular payload bytes;
only metadata and 64-byte recognized binary prefixes are retained. USTAR, GNU
long names/links and selected local PAX fields are supported. Sparse files,
devices/FIFOs, global PAX, size overrides, conflicting extensions, traversal,
duplicates, non-directory parents, dangling/cyclic/escaping links, truncated
members and nonzero TAR tails fail. Two zero end blocks and aligned zero
padding are required. Fixed-width TAR names end at the first NUL; genuine
install-only headers retain bytes from an older, longer path after that NUL.

Links resolve only against the archive inventory, including implicit directories
proved by existing descendants. They never consult host paths. Relative parent
components resolve after directory aliases. No files are opened on the basis
of archive or metadata path names.

Metadata version `"8"` must agree with the pinned version, target, build
options, conventional GIL, non-debug ABI and shared runtime configuration.
The runtime library must resolve to a regular file with an ELF64 little-endian
AArch64 ET_DYN header. Startup encoding sources, candidate `math`/`_ssl`
implementation resources and declared link resources must exist and have
inventory identities. These are format, identity and presence checks. They do
not validate an ELF dependency closure or prove interpreter initialization.
Upstream CRT claims are preserved verbatim, including a malformed trailing `)`
in this artifact's glibc version claim; they are not promoted to a release floor.

For install-only pairing, reproduce the exact reviewed upstream conversion at
the pinned source revision: omit material outside `python/install`, static
libpython archives, metadata-declared stdlib test packages and the specified
test extension images; project `python/install/*` to `python/*`. Compare every
retained entry's type, mode, size, digest and link identity. Additional, missing
or changed entries fail. Publish the omitted paths with their rule. Another
upstream revision requires filter review. Stripped artifacts and arbitrary uv
trees remain unsupported.

This inventory is separate from schema-zero resource packaging. Upstream
Unicode paths and Linux case-sensitive identities are retained; they are not a
claim of portable resource-path compatibility. The current manifest's bundled
stdlib names a single resource, whereas PBS describes a directory. Normalizing
that tree into a runtime resource inventory needs a separate decision.

## Findings and next gate

The pinned shared libpython is 73,563,968 bytes, exceeding the current controlled
Lua loader's 16 MiB per-image bound. Independent file inspection finds ABS64 and
TLSDESC relocations outside that loader's admitted subset. The actual libpython
inittab registers `math` and `_ssl`; separate extension images are not needed for
these particular startup imports. The inspector itself reports their metadata
as static-object candidates and leaves registration unobserved.

G0/G1 remain open. Stock PBS startup with archived encodings and no on-disk
Python home, isolated public-API embedding, compatible host-Python startup,
resource/import semantics and full no-payload-write execution traces are the
next A7 work. The Linux x86_64 release cell, macOS/Windows runtime loading and
FreeBSD's project-owned bundled producer still require their own evidence.
Do not relax loader admission limits to load this larger runtime without that
work. The report always sets `bootstrap_observed` and
`loader_compatibility_validated` to false.

The separate Linux evidence checker admits only the three declared inputs and
observed Rust/OS startup reads. It parses every syscall record, verifies two
complete compressed read passes per artifact and the returned stdout byte
total, and rejects unknown operations, attempted mutations, payload mappings
and additional processes. The report's contents and hash are checked separately
because strace abbreviates buffer contents. The full trace can be retained as
bounded gzip without dropping records. This observes the build-time inspector;
it is not Python execution evidence.

The inspected upstream rules are
[distribution metadata](https://github.com/astral-sh/python-build-standalone/blob/ccc07c40c2731bfb459c119f2388f65a5a470de6/docs/distributions.rst)
and the
[install-only conversion](https://github.com/astral-sh/python-build-standalone/blob/ccc07c40c2731bfb459c119f2388f65a5a470de6/src/release.rs#L470).
