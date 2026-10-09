# Signed macOS arm64 mapping probe

Status: A1 feasibility implementation on `codex/a1-macos-macho-probe`, from
merged `main` `a596305`. Debug and optimized signed captures from clean
implementation `346b2f0` pass the controlled fixture; see the
[retained evidence](../evidence/macos-arm64-macho-2026-10-09/README.md).

Add a separate `glue-macos-macho-probe` workspace executable, rather than a
product native capability. It packages and validates the exact two-image
fixture in the existing archive format. Its Lua manifest component is an
unacquired schema scaffold; this experiment does not start a runtime or change
the supported `glue run` profiles.

## Accepted image subset

The portable Rust parser accepts bounded little-endian arm64 `MH_DYLIB` images
with a zero preferred base, contiguous 16 KiB segment layout, classic dyld
pointer rebases, eager pointer bindings and regular export-trie entries. The
controlled closure has one archived dependency and one reviewed libSystem
`getpid` import. Validate both complete images, exports, import ordinals,
constructors, paths, all resource hashes and the exact manifest before any
executable allocation. Nonzero bind addends and undeclared symbols are rejected
by the fixture closure. Parser metadata limits and checked arithmetic bound
the work and allocation. Require the exact fixture build minimum macOS 13.0
and check the running host is at least 13; that declared minimum has not been
executed on a macOS 13 host.

Reject arm64e/PAC, universal/object/executable inputs, chained fixups, lazy or
weak binding, TLS/TLV, unsupported relocation/opcodes, reexports/resolvers,
Objective-C/Swift registration, unwind metadata and unknown load commands or
sections. Initializers must be validated C text pointers with a declared
rebase. Code-signature ranges are bounded opaque metadata, not authentication.
The positive build inputs are independently verified with `codesign`; copied
anonymous archive bytes do not acquire dyld's signature validation. The archive
remains trusted code, with hashes detecting corruption rather than authorship.

## Signing and memory mechanism

Sign the copied launcher ad hoc with hardened runtime and exactly
`com.apple.security.cs.allow-jit`. Keep library validation enabled and exclude
debugging, dyld override and unsigned-executable-memory entitlements. A
probe-only `csops(CS_OPS_STATUS)` query requires a valid hardened-runtime process
and rejects `CS_GET_TASK_ALLOW` or `CS_DEBUGGED`. Apple publishes this interface
and flags in XNU, but it is absent from the installed public SDK; production
API suitability remains a review gate. Retain actual signature flags and
entitlements after signing, not just the requested command arguments.

Apple documents a single `MAP_JIT` region for this hardened-runtime entitlement
and per-thread write protection on Apple silicon. Allocate one anonymous arena
for both images. On the observed host, changing `MAP_JIT` pages to ordinary RX
text or RW data with `mprotect` returns `EACCES`. Replace complete nonexecuting
pages inside the exclusively owned arena with ordinary anonymous `MAP_FIXED`
mappings instead. Every address is derived from a checked arena offset; the
archive cannot supply an arbitrary destination. This replacement is part of
the platform experiment, not an assumption about other macOS releases.

Copy and fix up code while the current thread's JIT write mode is enabled.
Restore execution mode on all exits and synchronize the instruction cache with
`sys_icache_invalidate` before calling native code. Final ordinary data pages
are RW and nonexecuting; constant data and link metadata are R. Text retains
VM-level RWX with Apple's per-thread hardware W^X policy. A VM region marked
RWX is therefore an explicit property of this mechanism; no ordinary RWX
allocation or file-backed executable payload is used. Do not call archive
constructors, callbacks or foreign code while JIT writing is enabled.

The initial signed fixture uses `pthread_jit_write_protect_np`. Adoption of
Apple's optional JIT callback allowlist is separate work: its entitlement
disallows that API and requires the callback-based writing interface. The
current probe is single-threaded; thread creation, constructor reentry, TLV,
unwind registration and V8 sharing of the one JIT arena remain unsupported.

Resolve `getpid` only through the reviewed system libSystem handle and verify
its actual implementation belongs to `/usr/lib/system/libsystem_kernel.dylib`.
Apply archived binding directly to the dependency's validated text export;
never expose its install name to a dyld payload-loading API. Finish all image
copies, fixups, protection transitions and cache synchronization before any
initializer. Pin the arena and OS handle for process lifetime before the first
native call, including every subsequent failure. Reviewed ordinary C fixtures
must not longjmp, throw foreign exceptions or reenter Rust mapping code.

## Evidence and open gates

Compare function, data, constructor count, repeated invocation and the OS PID
with ordinary dyld loading of the same compiled images. Remove all current-run
valid and adversarial build inputs before mapped execution. Relocate the
read-only archive and signed launcher to a directory containing spaces. Reject
seven real/mutated native images with exact diagnostics and statuses, including
a future-minimum regression. Record
signing controls, source/artifact identities and observed environment.

The local tracing tools cannot supply a full filesystem/VM trace under the
current rights: DTrace is denied, `fs_usage` needs root, Instruments needs full
Xcode, and `vmmap` cannot acquire the actual hardened process's task port.
Retain those failures. Do not add debugger rights or change SIP to manufacture
a passing observation. Input removal and exact output establish execution of
the fixture; they do not prove the absence of all failed filesystem mutations.
Independent no-extraction acceptance remains open.

Ad-hoc hardened-runtime execution also does not establish Developer ID signing,
notarization or distribution acceptance. No valid signing identity is available
on this host. These observations advance A1 but leave G0/G1 and four-OS
acceptance open. A general Mach-O backend and actual language-runtime startup
must follow the required platform and deployment evidence.

## Primary references

- [Apple silicon JIT guidance](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon?preferredLanguage=occ)
- [Allow JIT entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit)
- [Apple pthread interfaces](https://github.com/apple-oss-distributions/libpthread/blob/main/include/pthread/pthread.h)
- [XNU mmap implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_mman.c)
- [XNU VM protection policy](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_map.c)
- [XNU code-signing operations](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h) and [flags](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [Notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
