# Foundation contract (A0)

Status: accepted for the experimental implementation, 8 October 2026.

The runtime contract in `PLAN.md` remains binding: no payload extraction,
temporary payload files, runtime downloads, compilation, mounts or silent host
fallback. Anonymous kernel memory objects are permitted only when the backend
reports their use. Application output is separate from archived resources.

## Version and ownership

The manifest and container use experimental version **0**. Version 1 is not
frozen: ZIP64 remains a candidate pending the Node VFS reuse probe. The initial
workspace pins Rust 1.88.0 and checks in Cargo.lock. New archive, validation,
resource and orchestration code is Rust; there is no link-time dependency on a
language runtime.

`glue-format` owns manifest validation, resource identities and the archive
container. `glue-resources` will own the read-only tree and memory cache.
`glue-pack` will own builder filesystem access; `glue-runner` will expose the
`glue` command. Read-only archive access must never call an extraction API.
Manifest validation checks declarations; it is not native compatibility evidence.

Runtime selection is explicit and immutable during acquisition. Bundled specs
carry an exact source pin, runtime build identity and archived library/stdlib
references. Host specs carry explicit library/stdlib locations and the same ABI
requirements. A provider must validate library and stdlib identity before
initialization and keep the acquired native handle alive. No PATH, user-site,
environment or network discovery is implied. Python must retain one runtime
identity; Node source/bridge revisions must match; Lua numeric configuration
must be explicit. Provider implementation is a later gate.

Native images are pinned for the process lifetime. A symbol lease owns a module
reference; failed partial initialization publishes no symbols. Native dependencies
are explicit edges to archived modules, runtime exports, approved OS libraries or
declared host modules. Requested loader features are declarations until a backend
publishes execution evidence. Missing features must reject execution before any
constructor or interpreter initialization.

## Portable resource identities

Experimental paths use printable ASCII components, `/` separators and relative
identities. They reject traversal, empty components, backslashes, drive names,
control characters, Windows reserved names and trailing dots/spaces. File names
and implicit directory names must not collide under ASCII case folding. Unicode
payload names require a future normalization/case decision; host archive filenames
and builder directories may contain spaces and Unicode. Symlinks are not part of
this initial resource model. An origin such as `glue://app/main.lua` is a diagnostic
identity, never a promise of an OS pathname.

Uncompressed resource hashes and source-artifact hashes are separate SHA-256
identities. The archive locator carries the manifest digest; this detects accidental
corruption but is **not** authentication. An attacker can replace both bytes and
hashes. Archive identity does not replace code signing or a trusted signature.

## Candidate profiles and open evidence

| Candidate | Runtime source strategy | Unresolved evidence |
| --- | --- | --- |
| Linux x86_64 / glibc | Stock shared PBS CPython; pinned Node; official Lua 5.4 | Executable sealed memfd, dependency routing, libc floor |
| macOS arm64 | Stock shared PBS CPython; pinned Node; official Lua 5.4 | Signed Mach-O mapping, fixups, JIT policy, TLV/unwind |
| Windows x86_64 / MSVC | Shared PBS Python DLL; pinned Node; official Lua 5.4 | PE imports/runtime aliases, TLS, exception tables |
| FreeBSD amd64 | Project-produced shared CPython and Node; official Lua 5.4 | Producer recipe and exact pins, shm/fdlopen execution |

Exact minimum OS versions, page sizes, CPU features, approved OS-library lists,
runtime revisions and artifact digests must come from the G1 fixtures. Do not
fill these with moving releases or synthetic hashes and call them release pins.
The format can encode them now; no bundled-runtime lock is advertised yet.

**G0 remains open** until all four profiles have real source pins and the signed
macOS deployment experiment. **G1 remains open** until native modules and runtime
bootstraps execute on native OS runners. Cross-compilation and synthetic archive
fixtures cannot close either gate.
