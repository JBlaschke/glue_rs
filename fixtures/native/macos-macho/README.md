# Controlled signed macOS arm64 Mach-O fixture

This A1 feasibility input compares ordinary dyld loading with the experimental
`glue-macos-macho-probe` mapper. It exercises an archived dependency, four
function/data exports, an actual initializer pointer and the reviewed OS import
`getpid` from `/usr/lib/libSystem.B.dylib`. Its declared Lua component is an
unacquired schema scaffold. It does not start a language runtime.

The dependency returns 35; the module adds its exported data value 7. A volatile
counter preserves a real `__mod_init_func` initializer that must run once. The
module reports the target PID through its bound OS import. The ordinary dyld
baseline opens the same two signed binaries and checks that a repeated open
preserves the module identity and initializer count.

The build requires local Apple arm64, a 16 KiB target page profile, the command
line developer tools and the selected classic dyld fixups. Compiler flags
remove stack-protector imports and unwind metadata; linker flags request
`-no_fixup_chains`, `-bind_at_load` and `-no_compact_unwind`. Load-command, symbol,
dyld-fixup and code-sign reports are retained. The linker still declares
libSystem for the dependency, even though that image has no bound OS symbols.

After building the Rust probe and packaging CLI, capture a fresh run:

```sh
sh fixtures/native/macos-macho/run.sh \
  "$PWD/target/debug/glue" \
  "$PWD/target/debug/glue-macos-macho-probe" \
  "$PWD/target/evidence/macos-macho/capture-1"
```

The output directory must not already exist. The harness builds an explicit
archive through `glue build`, captures the ordinary comparison, then signs a
copied launcher ad hoc with hardened runtime and exactly the
`com.apple.security.cs.allow-jit` entitlement. It does not grant unsigned
executable memory, debugging, dyld-environment or disabled-library-validation
entitlements. The signed launcher and read-only archive are relocated into a
directory with a space in its name. All current-run valid and adversarial
compiler input trees are removed before native archive execution. Every harness
command script is copied into the record, and `source.sha256` inventories tracked
crate, spike and fixture sources plus the workspace lockfile/toolchain inputs.
Retained captures should be taken only after these sources are committed.

Seven archive cases preserve resource hash validation but reject unsupported or
inconsistent native metadata: wrong architecture, mismatched install name,
chained fixups, thread-local variables, writable executable text and an
undeclared dependency and a future minimum OS version. The future-version
case preserves a valid load command but changes both `LC_BUILD_VERSION` minimum
OS and SDK versions to 99.0; the closure requires the selected 13.0 image
profile exactly. Chained-fixup and TLV images are genuine compiler/linker
outputs; the other cases are bounded build-time byte mutations. The genuine
chained image also uses `__init_offsets` and rejects at that unsupported section;
the TLV image rejects at its header's TLV flag. Exact diagnostics, empty stdout
and exit status 1 are checked for every case. The exact
successful stdout is `PASS answer=42 data=7 constructors=1 pid=N` plus a newline,
with empty stderr. PID-normalized output must match ordinary loading.
`check-results.py EVIDENCE_DIRECTORY` repeats the result checks independently.

Two extra copies exercise the actual signing policy against the valid archive.
A hardened-runtime copy with no JIT entitlement must reject at executable
mapping; a copy granting both `allow-jit` and `get-task-allow` must reject at the
probe's process-signature guard. Both controls require exact diagnostics, empty
stdout and status 1. Their signatures, entitlements and process-policy masks are
retained. CodeDirectory flags are not the process `csops` value; the mask record
identifies the guard's required and disallowed process bits. The successful
launcher keeps only `allow-jit`; rejected controls
establish neither distribution acceptance nor a permissive release profile.

A separate signed memory-policy fixture uses the same sole `allow-jit`
entitlement. On this observed host it requires both RX and RW `mprotect`
demotions of JIT pages to fail with `EACCES`. It then replaces the owned data
page with ordinary anonymous RW memory, enables JIT write protection, executes
arm64 code returning 42 and writes the ordinary data value 8. Exact output,
empty stderr, signature records and status 0 are retained. This supports the
mapper's memory mechanism on the observed cell; it does not prove an independent
VM trace or test forbidden code writes by inducing a process fault.

The harness also holds the actual signed target for ten seconds and attempts
`vmmap` after its result is ready. It records unprivileged DTrace, `fs_usage` and
Instruments availability checks. These tools can be denied by the host security
or developer-tool configuration. Such denials remain in the records; the
harness does not use sudo, change system security or broaden launcher
entitlements. Input removal, loader records and a VM snapshot do not establish a
complete filesystem trace. Independent no-extraction acceptance remains open
until a permitted complete trace is captured.

Ad-hoc signing demonstrates one local hardened-runtime experiment. It does not
establish Developer ID signing, notarization, distribution acceptance, general
Mach-O compatibility or an extension/package ecosystem. The mapper's supported
segments, imports and fixups are deliberately bounded by its preflight parser.
