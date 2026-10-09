# Signed macOS arm64 Mach-O evidence — 2026-10-09

This bundle records a separate A1 feasibility probe at clean implementation
`346b2f0136b15abad6cd2818c1bcc217071309f1` on
`codex/a1-macos-macho-probe`, from merged `main` `a596305`. Both debug and
optimized launchers pass the controlled experiment. It advances signed native
mapping; full independent write tracing and distribution signing remain open.
See [ADR 0009](../../decisions/0009-signed-macos-macho-probe.md).

| Validation | Observed result |
| --- | --- |
| Mac/Linux source workspace tests, Lua 5.4 / 5.5 | 212 / 213 passed on both systems |
| Mac/Linux all-targets workspace Clippy, both profiles | passed with `-D warnings` |
| Portable Mach-O parser tests | 31 passed, including optimized Mac build |
| Signed debug and optimized relocated execution | exit 0; exact stdout; empty stderr |
| Ordinary dyld loading of the same compiled images | matches after PID normalization |
| Seven native rejection cases per launcher | exact diagnostics, status 1, empty stdout |
| Two signing controls per launcher | exact policy/allocation rejection, status 1 |
| Signed memory-policy control | exact expected results, exit 0 |
| Linux execution of the macOS probe | unsupported, status 2 |

The positive outputs are:

```text
PASS answer=42 data=7 constructors=1 pid=24781
PASS answer=42 data=7 constructors=1 pid=24792
```

These check an archived dependency returning 35, exported function/data,
one real constructor, repeated calls and a reviewed OS `getpid` binding. The
baseline additionally reopens the ordinary dyld module and checks identity and
constructor count. The probe never acquires its manifest's Lua scaffold or any
language runtime, and does not enable macOS native loading in `glue run`.

## Signing and mapping

The copied launchers are ad-hoc signed with hardened runtime. Independent
signature checks retain actual `flags=0x10002(adhoc,runtime)` and exactly
`com.apple.security.cs.allow-jit=true`, without debugger or unsigned-memory
entitlements. See [debug](debug/launcher-signature/identity.stderr.txt) and
[optimized](release/launcher-signature/identity.stderr.txt) signatures and their
entitlement files. The mapper queries the current process's signing policy and
rejects debugger access; CodeDirectory flags and process flags are distinct.

One anonymous `MAP_JIT` arena contains both validated images. Nonexecuting
pages are replaced with ordinary anonymous pages inside the exclusively owned
range. The signed [memory-policy result](debug/memory-policy/probe.stdout.txt)
demonstrates why: direct RX/RW `mprotect` demotions of JIT pages fail with
`EACCES`, while ordinary owned data replacement allows writes after enabling
JIT execution. Code pages retain VM-level RWX and use Apple's per-thread
hardware W^X mode. The Rust mapper copies/fixes code in writing mode, restores
execution mode, synchronizes the instruction cache, makes constant data R,
and calls constructors only after preparing the entire closure. Mappings stay
pinned until process exit. This is trusted ordinary C code, with no supported
TLS, foreign exceptions or constructor reentry.

The positive images have classic pointer rebases/eager binds, regular exports,
no weak/lazy streams and no unwind/TLV metadata. The module's actual initializer
and two import slots are visible in the [dyld inspection](debug/libglue_probe_module.dyld-info.txt).
Apple's `dyld_info -opcodes` output repeats the eager bind bytes under a lazy
heading; the [load-command fields](debug/libglue_probe_module.load-commands.txt)
declare `lazy_bind_off=0` and `lazy_bind_size=0`. Preflight reads those actual
bounded metadata fields rather than inferring a lazy stream from the label.
The parser bounds code-signature metadata but does not authenticate it.
Successful inputs are independently `codesign` verified before packaging;
anonymous copied bytes are not registered as dyld-validated signed images.

| Rejection case | First observed rejection |
| --- | --- |
| Wrong architecture | arm64 `MH_DYLIB` header requirement |
| Install name mismatch | exact controlled closure identities |
| Genuine chained-fixup image | unsupported `__init_offsets` section, before chained command |
| Genuine TLV image | unsupported TLV header flags |
| Writable/executable text | segment protection validation |
| Undeclared dependency | exact declared dependency closure |
| Future minimum macOS 99.0 | exact fixture minimum macOS 13.0 |

All seven have hash-valid archives and exact recorded diagnostics. Parser tests
also directly reject chained commands and TLV sections. The future-minimum
case is a regression for a review finding: the parser retains the minimum and
the fixture closure checks it before mapping. Results are
[debug](debug/result-check.txt) and [optimized](release/result-check.txt).
The signing controls independently exercise a hardened launcher without JIT
rights, whose allocation fails, and a JIT launcher with debugger rights, whose
process-policy check rejects. Neither weakens the positive launcher's profile.

## Environment and reproducible records

The observed host is macOS 26.7 (25G229), Darwin 25.6.0, arm64 with 16 KiB pages
and SIP enabled. Tooling is Rust/Clippy 1.88.0, Apple clang 21.0.0
(`clang-2100.3.34.2`), linker `ld-27037.1` and SDK 27.0. Fixtures declare macOS
13.0 and compile C with `-O2 -g0`; that minimum was not executed on a macOS 13
host. Debug and optimized Rust launchers load the same positive archive,
SHA-256 `aa82171658f2e43e6ee73b16159c763b77bc4d8ca15e82d2af68a84069c2c649`.
Exact signed executable hashes are in the
[debug](debug/execution-artifacts.sha256) and
[optimized](release/execution-artifacts.sha256) records.

Each profile retains the invocation, every command script, clean Git status,
65 source hashes, compiler/environment metadata, native and archive identities,
load commands, symbols, fixups, signatures, statuses and exact stdout/stderr.
Both captures remove the entire current-run valid/adversarial build inputs
before mapped execution. The signed launcher and read-only archive run from a
relocated directory containing spaces. All sixteen archives and their three
members were verified in memory; source hashes match clean Git blobs and copied
records were compared byte-for-byte. See [verification.txt](verification.txt).
Binaries and archives are excluded from this text bundle.

Workspace test/Clippy records are in `validation/macos` and `validation/linux`;
[context.txt](validation/context.txt) attributes them to the identical committed
source. Linux ran offline in the same immutable arm64 Podman image used by the
earlier Linux evidence, with a read-only repository and ephemeral build storage.
Its script is [retained](validation/linux-validation.sh). Linux tests portable
metadata validation and unsupported-platform behavior, not macOS execution.
[SHA256SUMS](SHA256SUMS) covers all bundle files except itself; verify from this
directory with `shasum -a 256 -c SHA256SUMS`.

## Open acceptance evidence

DTrace and `fs_usage` capability probes fail under the current rights;
Instruments is unavailable with only command line tools. `vmmap` also fails to
acquire the task port of each actual signed held target (status 255). The held
PID and exact output are checked. Retained
[tracer denials](debug/trace-availability/scope.txt) and
[target VM denial](debug/held-probe.vmmap.stderr.txt) are limitations, not passing
trace evidence. No sudo, SIP change or debugger entitlement was added to the
positive profile. Input removal and matching output do not establish the
absence of all failed filesystem writes.

The local identity query reports no valid code-signing identities. Ad-hoc
execution does not establish Developer ID signing, notarization or clean-host
distribution. Complete independent filesystem/VM tracing, release API review,
general Mach-O features and actual language-runtime startup remain work for A1.
G0/G1 and four-OS acceptance remain open.
