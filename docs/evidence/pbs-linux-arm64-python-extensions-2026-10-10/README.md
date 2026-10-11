# Registered Python native initializers — GNU Linux arm64

Stock CPython 3.13.16 / PBS `20261009` ran four reviewed native modules and their
private dependency on 2026-10-10. Bundled/explicit-host runtime providers and
archived/explicit-host native providers varied independently over four cells.
All four successful cells and matching app-error cases passed; archived
corruption and missing/wrong host images rejected before runtime mapping.
Seven host-import, three bundled-import, four frozen-startup and eight
host-startup regressions also passed, giving 33 complete retained traces.

Every capture uses clean implementation `b784c99897774adef8fea39e08f33404de51a5b2` on
`codex/a7-python-extension-init-bridge`, from merged
`a50b654762cc734694f307dbf5827488abbcb628`. Captured source status/diffs are
empty. `source.sha256` identifies all 210 tracked source files at that
checkpoint, excluding evidence directories. This following commit adds the
retained evidence and documentation links.

## Inputs and observed cell

The immutable image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, with
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
Rust 1.88.0, Debian bookworm, Linux `7.1.4-200.fc44.aarch64`, glibc
`2.36-9+deb12u10`, GCC 12.2.0, strace 6.1 and 4,096-byte pages are recorded in
`environment.txt` and `image-inspect.json`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Release launcher, identical in all five captures | 3,520,088 | `29de143a54d6a2f41ce2324d92f52edc12b0f33773a283f81d2b8dc95a145c36` |
| bundled-archived archive | 83,438,354 | `db387750e1d79b9e16d6ec3553ce19e867b3272115c4232994e2925440542a97` |
| bundled-host archive | 83,094,831 | `aab881196962c0fb25d4a0874baccfc0e2049f2ab344f6cd70596f347bc984d5` |
| host-archived archive | 359,787 | `7c8d5f07bdef95c89ba5dd38cfc85a19bdefcc29b8e2875a34d4197bc0a1ec00` |
| host-host archive | 16,264 | `524ec61d5705cf3276cd9fb52e6f5c4ae428e0a3de15067347b9e90b835091c4` |

All five capture groups have exactly the same launcher SHA-256. The unchanged
selected libpython has 73,563,968 bytes and SHA-256
`42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219`.
The 139,523-byte matching-producer startup bundle has SHA-256
`6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`.
`upstream-pins.json` and `freeze-provenance.json` retain exact upstream/producer
and 264-header identities. Host runtime sources retain the existing reviewed
69-source closure. The bundled source inventory remains the existing pinned
2,174-file projection. Prior profile summaries retain their individual identities.

`native-images/` retains the five actual fixture ELF files, totaling 341,400
bytes. Each root exports exactly its `PyInit_*` function, needs the private
`libglue_python_dependency.so` and `libpython3.13.so.1.0`, and imports only
reviewed public Python functions/data. The dependency exports one function and
needs no library. These images have no constructors, TLS, IFUNCs, versions,
weak/private API imports or additional dependencies. `native-build/` retains
compiler, ELF, undefined-symbol and hash records, plus the independent stock
registration driver's source and artifact identity. Its 69-byte native result
matches the suffix of each 169-byte successful app result, with exit 0 and
empty stderr.

The exact seven canonical manifests are retained in `manifests/`, independently
verified against their locator hashes. `native-metadata.json` records sizes,
SHA-256, exact PT_LOAD facts, provider declarations, manifest/ZIP-directory
bounds and the corrupt dependency offset. `fixture-summary.json` checks actual
native files against each manifest and records every archive's identity.
The corruption control changes exactly the first stored dependency byte
`0x7f` to `0x7e`; the whole archive comparison confirms no other byte changed.

## Runtime behavior

Admission verifies the complete archive into memory and closes it before any
host query. Every native image is bounded to 256 KiB and inspected before code
loading. Archived images use five executable memfds, completely populated and
sealed before the first native alias is opened. Explicit host images use
bounded no-follow reads through verified live ancestor/file descriptors, two
complete hash/inspection snapshots, EOF checks and rewinds. The external
installation remains immutable and read-only throughout execution; descriptor
retention alone does not freeze mutable backing bytes.

The selected Python runtime remains `RTLD_LOCAL`. Native loading uses
`RTLD_NOW | RTLD_LOCAL`, dependency first. Exact SONAME reuse is followed by
checking every function, data and relative relocation against its admitted
provider, every initializer's address/owner, and the complete loader image set.
No second runtime or undeclared dependency is admitted. Public Python/native
symbols remain absent from global lookup. Loaded descriptors and loader
handles stay pinned through finalization and until process exit, including
later failure paths.

C boundary revision 4 has 29 acquired public exports, a 240-byte table and
16-byte registration records. It validates reviewed unique top-level names and
addresses before Python calls, copies names, and invokes public
`PyImport_AppendInittab` before `Py_InitializeFromConfig`. Copied names stay
pinned from the first registration attempt, including partial failure. No
Python object crosses Rust; the existing source/resource callbacks remain live
through `Py_FinalizeEx`. Build records prove no linked Python API symbols.

Stock `BuiltinImporter` owns both initialization protocols and reports honest
`origin="built-in"` metadata, no file/cache location, and registration in
`sys.builtin_module_names`. The single-phase `m_size=-1` module initializes once:
reload preserves it and removal/reimport restores the original shallow module
dictionary without reinitialization. Method objects remain shared. The
multi-phase module uses default creation and per-module state: reload preserves
state; removal/reimport creates and executes fresh state. Controlled initializer
and exec-slot failures leave no incomplete cache entry and succeed on retry.
A method exception leaves its existing module usable. The app's silent `atexit`
callback calls retained old/new modules and their private dependency during
actual finalization, alongside the existing archive resource callback.

The separate runtime cell runs UID/GID 65534, offline, from an empty directory,
with read-only root/build mounts, no workspace mount, unavailable HOME/TMPDIR,
mode-000 `/tmp`, and poisoned Python variables. Producer executables, matching
headers and Cargo/native build intermediates are removed first. Paths contain
spaces. The traced launcher writes only to inherited stdout/stderr;
`commands.sh`, `runtime-identity.txt`, `runtime-mounts.txt` and
`post-removal-files.txt` retain setup and file inventory.

| Mode | Exit | Stdout / stderr bytes | Trace records |
| --- | ---: | ---: | ---: |
| `bundled-archived` | 0 | 169 / 0 | 33,681 |
| `bundled-host` | 0 | 169 / 0 | 33,798 |
| `host-archived` | 0 | 169 / 0 | 5,873 |
| `host-host` | 0 | 169 / 0 | 5,991 |
| `bundled-archived-app-error` | 1 | 169 / 66 | 33,695 |
| `bundled-host-app-error` | 1 | 169 / 66 | 33,798 |
| `host-archived-app-error` | 1 | 169 / 66 | 5,886 |
| `host-host-app-error` | 1 | 169 / 66 | 5,992 |
| `corrupt-native` | 1 | 0 / 102 | 26,563 |
| `missing-host-image` | 1 | 0 / 164 | 33,361 |
| `wrong-host-image` | 1 | 0 / 134 | 33,413 |

Successful output is exactly:

```text
PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42
GLUE_PYTHON_EXTENSIONS_PASS single=42 multi=44 retry=2 dependency=42
```

The four app-error cells print the same output before the exact controlled
application diagnostic. All three native admission controls print no stdout,
map no runtime/native code and attempt no fallback.

## Checks and replay

Mac and GNU Linux arm64 workspace checks pass 338/339 tests for Lua 5.4/5.5,
with all-target Clippy warnings denied. The portable Python profile has 59 tests;
the opt-in GNU boundary/profile run passes 65 release tests and Clippy in each
capture. All 191 trace-policy tests, including 30 native registration checks,
pass on Mac and the pinned stock Linux interpreter. Both 16-test importer
protocol runs pass. Logs and commands are retained in `validation/` and the
workspace/policy command files. `retention-commands.py` records archive,
manifest, member, compression, replay and source-identity checks;
`validation/retained-integrity-audit.json` records the independent integrity
review with no findings.

All 33 raw traces are deterministically gzip-compressed and replayed through
their strict complete-trace checker. `trace-summary.json` records raw/gzip
hashes, record counts and PIDs; each compressed replay has output and exit
status. The new checker verifies native preparation/seals, live descriptor and
ancestor identities, exact aliases/mappings/guards/RELRO/trims, protected
runtime/native lifetimes and negative admission coverage/diagnostics, then
replays all remaining records through unchanged source/import runtime policies.
Archived corruption requires complete locator, manifest, ZIP directory and
selected payload coverage before its diagnostic. Every record is accounted
for; no parent file/mapping policy is weakened.

An independent audit accepts all 11 new compressed baselines and rejects all
37 hostile edits. Its unchanged script and exact edit/hash/rejection log are
retained in `validation/independent-trace-audit.py` and
`validation/independent-trace-audit.json`. The audit ran while implementation
and captured revisions matched and both were clean. Controls include fresh
ancestor metadata, native/runtime remapping and protection changes, descriptor
collision, incomplete seals/population/closure, alias/order errors, fallback or
materialization, stream identities, corruption coverage and post-rejection
acquisition. These checks validate this reviewed experiment, not a native-code
sandbox.

Replay one new retained trace from the repository root:

```sh
python3 scripts/check-linux-python-extension-trace.py \
  docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/bundled-archived.trace.txt.gz \
  --mode bundled-archived --archive-bytes 83438354 \
  --native-metadata-file docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/native-metadata.json \
  --stdout-file docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/bundled-archived.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/bundled-archived.stderr.txt
```

The corrupt replay additionally requires the retained `--corrupt-native-offset`
value from `fixture-summary.json`. `SHA256SUMS` covers every retained evidence
file other than itself. `capture-summary.json` ties all five capture groups to
the same source/launcher. The independent audit can be rerun with its capture
argument set to this evidence directory; omit `--require-clean` when replaying
from the later evidence commit.

## Scope

This is a controlled registered-initializer experiment for the exact reviewed
CPython 3.13.16 / conventional GIL / GNU Linux arm64 profile. General
`ExtensionFileLoader` metadata/discovery, arbitrary wheels or extensions,
mutable host installations, custom create slots, explicit `m_free`/GC teardown
instrumentation, subinterpreters, unloading, debug/free-threaded ABIs, variable
Python versions and other platforms remain open. Product Python execution and
provider acquisition/integration remain open. G0/G1/G2 and platform/release
acceptance remain open; this evidence does not close them.
