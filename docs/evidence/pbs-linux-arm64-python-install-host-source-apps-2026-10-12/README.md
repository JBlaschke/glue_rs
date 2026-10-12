# Install-only host Python source application evidence — GNU Linux arm64, 2026-10-12

These optimized captures use clean implementation
`7a8e32c54d0375a755b55a679e18ef97e6c50114` on
`codex/a7-install-only-host-source-apps`, from merged `442d9eb`. Captures and
retention ran on 2026-10-12. The product uses default linked Lua 5.4 plus
`python-pbs`; historical thin probes use the same shared Python executor.
The new harness's `development-opt-in.txt` is `false`.

All **77 complete traces** pass live checks and compressed-file replays:
16 new install-only host cases and 61 fresh regressions. Those regressions
cover full-source host apps (13), bundled source apps (6), the original product
registry (9), native initialization (11), host archive imports (7), bundled
archive imports (3), frozen startup (4) and installed-host startup (8).
Historical harnesses and trace policies remain unchanged.

## Observed cell and validation

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`
(repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`).
The GNU Linux arm64 cell uses kernel `7.1.4-200.fc44.aarch64`, glibc
`2.36-9+deb12u10`, 4,096-byte pages, Rust 1.88.0, GCC 12.2.0 and strace 6.1.
Runtime pins remain stock CPython 3.13.16 / PBS `20261009`, conventional GIL
and non-debug mode.

| Validation | Result |
| --- | --- |
| Mac arm64 source workspace, Lua 5.4 / 5.5 | 395 / 396 Rust tests; all-target Clippy with warnings denied |
| Mac arm64 Python-enabled workspace | 395 Rust tests; all-target Clippy with warnings denied |
| GNU Linux arm64 source workspace, Lua 5.4 / 5.5 | 395 / 396 Rust tests; all-target Clippy with warnings denied |
| Every optimized GNU shared Python/probe build | 116 Rust tests; all-target Clippy with warnings denied |
| Optimized GNU product runner | 14 CLI tests; all-target Clippy with warnings denied |
| Trace-policy suite, Mac / pinned stock Linux Python | 288 / 288 tests |
| Importer and byte-entry protocols, both interpreters | 16 and 7 tests |
| Host source protocol, Mac / pinned stock Linux Python | 11 tests with 2 stock-only skips / all 11 pass |
| New install-only product controls | All 60 exact controls agree |
| Full-host / bundled-app / original product controls | All 51 / 34 / 30 exact controls agree |
| Independent hostile edits of actual new traces | All 894 reject, from 16 passing clean baselines |
| Compressed trace replays | All 77 exit 0 |

The 60 new controls comprise 15 successful new-profile builds, four read-only
commands for seven app/archive cases, nine damaged-host doctor calls, three
rejected build declarations, two rejected doctor declarations, and the old
full-source profile's build/doctor/run against the stock installation.
Expected outputs bind to actual archive hashes, canonical manifests and entry
bytes. Declaration errors reject before input-root lookup or output creation.
Doctor reports declarations/build/target readiness without inspecting a host.
The old full-source profile rejects the missing `idlelib/idle_test` directory;
it does not silently select the install-only subset.

## Artifacts and outcomes

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Product release `glue` | 3,932,048 | `e4018ce501a87ebb8a78097be31dc03ca6a94fea938a3775bab32093a4cb8d47` |
| Shared thin regression probe | 3,190,064 | `1d0a89a24d40a07e47dc3763ba45037c4bad9639ef5da7630cd69f53f5d7210a` |
| minimal archive | 6,512 | `9e0ea575020252467eaf2aa81aa76efafbdbeb16e371f254de117db52d5cf975` |
| resources archive | 9,793 | `7cb47576f8c9de5f94e421afbd81148ae3b0e82e657a9892ed98ce5b11352527` |
| stdlib archive | 6,779 | `44b3c9a74e45372da7d3dcab696a3fd46b44bb82b5ec003007c903abfcbffb03` |
| Installed `libpython3.13.so.1.0` | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |
| Pinned install-only upstream artifact | 57,626,877 | `397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34` |

| Mode | Exit | Stdout / stderr bytes | Trace records |
| --- | ---: | ---: | ---: |
| `minimal` | 0 | 50 / 0 | 12,802 |
| `resources` | 0 | 90 / 0 | 12,885 |
| `stdlib` | 0 | 76 / 0 | 12,807 |
| `app-error` | 1 | 0 / 43 | 12,795 |
| `syntax` | 1 | 0 / 42 | 12,794 |
| `nul` | 1 | 0 / 69 | 12,794 |
| `corrupt-source` | 1 | 0 / 70 | 161 |
| `missing-source` | 1 | 0 / 154 | 3,169 |
| `wrong-source` | 1 | 0 / 131 | 3,177 |
| `deep-cache` | 1 | 0 / 165 | 746 |
| `startup-native` | 1 | 0 / 190 | 928 |
| `startup-bytecode` | 1 | 0 / 163 | 927 |
| `missing-library` | 1 | 0 / 143 | 1,043 |
| `missing-cache` | 1 | 0 / 62 | 936 |
| `wrong-cache` | 1 | 0 / 155 | 946 |
| `extra-cache` | 1 | 0 / 179 | 937 |

Entries/imports/resources reuse the earlier paired app fixtures, including
quoted filenames, namespaces, stream reads, byte-source compilation and
finalization reads. `stdlib` exercises fractions, statistics, XML and a source
resource stream. Source, standalone-bytecode and native lures cannot become
default imports, nor can an unknown descendant below an owned stdlib package.
Syntax, NUL and application exceptions retain the bounded status-1 contract.

The new archives contain only the original pinned importer and app-owned files.
Their small sizes rely on declared installed prerequisites: the exact library,
1,037 sources totaling 15,894,268 bytes, and three startup caches totaling
21,157 bytes. All sources match their identities in the full distribution.
The 1,137 omitted files are exactly 1,072 under `test/` and 65 under `idlelib/`;
the runtime-name collision set remains the full provider's reserved set.
Both inventories include 122 encoding sources and 404 site-packages sources.
Pinned site-packages bytes are not automatically exposed as top-level imports.

## Complete stock installation and startup

The helper hashes a bounded owned snapshot of the complete compressed artifact
before bounded tar parsing or materialization. Ordinary staging needs neither
a runtime archive nor an installed provider. Building the fixture's matching
headers and freeze compiler still uses the existing full input; that is a
build/test prerequisite, distinct from install-only product staging.

The complete upstream installation has 3,478 regular files totaling 182,155,939
bytes and 1,048 symlinks. It includes case-distinct terminfo entries that cannot
coexist on the Mac's filesystem. The fixture therefore builds and runs on an
ephemeral Linux Podman volume, preserving all stock bytes, symlink targets and
normalized mtimes. Read-only modes are an explicit transformation. The primary
runtime tree adds nine documented import lures; nine additional trees contain
only their declared missing/corrupt source/library/cache or startup controls.
The ordinary helper without `--controls` does not add those lures.

An independent post-runtime audit re-decodes and hashes all upstream regular
members, compares complete materialization provenance, then verifies every
file and symlink identity, their exact nanosecond mtimes, directory inventory
and read-only modes in all ten provider trees. Verified hardlink identities avoid hashing duplicate inodes.
The audit and volume-removal receipts are retained. Only launcher/archive bytes
are exported to the Mac; no complete provider tree is assumed to remain there.
The physical stock interpreter, headers, native files and data remain in the
selected provider. The runtime does not invoke a separate interpreter.

| Stock startup cache | Bytes | SHA-256 |
| --- | ---: | --- |
| `encodings/__pycache__/__init__.cpython-313.pyc` | 6,289 | `ffc86018b4472655c7e7e751d81388f680be37462465346899cca17cc4f38a45` |
| `encodings/__pycache__/aliases.cpython-313.pyc` | 12,563 | `61115bc7158a7bf19c18c58d5671343479927464eeb5a0c894519c18e6c22084` |
| `encodings/__pycache__/utf_8.cpython-313.pyc` | 2,305 | `27f9809d7346fd60f4f94be674cb6dd9ef51e58dbed99ee1896b599cb526f015` |

Runtime admission requires those exact cache bytes and a closed cache directory.
Every other derived cache location and startup shadow rejects. Stock source/
cache mtimes are `1704067200`; the timestamp-based cache headers encode
`1791559484`. Each initialized trace fully reads and closes each stale cache,
then reads the matching encoding source. Normalized mtimes are an independently
audited preparation/conformance fact; runtime admission hashes bytes and checks
path identity without requiring every file's mtime to equal that stock value.
This observation does not imply identical cache selection for all installations.

## Runtime and trace contract

Runtime containers are offline, unprivileged and read-only, without workspace
or separate producer/build inputs. Working directories are empty, temporary
paths unavailable and Python environment variables poisoned. Installation and
startup paths must remain immutable/read-only through execution/finalization;
mapped library backing must remain immutable for process life.

Archive admission verifies app/helper contents and closes the archive before
host acquisition. Exact cache owners are verified and rewound before library,
startup and source-snapshot reads. Cache, six startup and directory leases
remain live through finalization; individual snapshot descriptors close promptly.
The 100 source directories plus one cache directory have deduplicated owners.
Portable validation enforces 256 distinct directory owners and a separate
763-total-owner cap. With `P` including root through stdlib, retained ownership
is `10P+115`: 61 prefix components admit 755 owners; 62 would require 765 and
reject before I/O. This prevents the smaller source inventory from silently
allowing unsafe descriptor growth. Initialized captures retain 165 runtime
owners, peak at 169 total descriptors including inherited streams and a
temporary file, and end with only the streams and pinned library descriptor.

The unchanged trusted prelude disables default filesystem import fallback
before the original importer runs. Later source modules and resources consume
owned bytes with virtual origins; initialized host/frozen metadata remains
stock. Source snapshots do not freeze mutable library backing or all startup
pathname lookups. Trusted code may change import machinery or perform host I/O.

The separate strict checker binds typed provider/target/inventory, canonical
archive layout, exact command, inherited streams, diagnostics/status and one
readiness event after metadata but before payload/host reads. It checks complete
source/library/cache byte coverage, EOF/rewind, fresh no-follow metadata before
checked opens, closed startup/cache directories and held owner lifetimes.
It also checks the visible ELF prefix, loader alias header/fstat, RX/RW order,
reservation/guard/BSS/RELRO changes, alias closure and image lifetime through
exit. There is no memfd or archived-provider fallback in this host route.
Forbidden filesystem fallback, executable-memory changes and process/thread
creation attempts reject even when the syscall fails.

Initialized cases have the observed 2,496-byte Python entropy request, one TID
query and four exact anonymous remaps. These new-profile observations do not
widen older policies. Success output precedes retained owner release; error
cases combine synchronous Rust/C ownership with complete phase/closure traces,
because owners drop before the outer diagnostic. Tracing uses `-s 256`;
returned/requested counts prove coverage and visible prefixes, while complete
hashes come from actual inputs/runtime verification and the provider audit.
Truncated strings do not independently hash every source/library/cache byte.

All 894 hostile edits reject, including startup/cache owner release before
loading/output, stale metadata reuse, incomplete cache coverage/EOF/rewind,
extra cache entries, missing cache/source pairs, late source/cache filesystem lookups and
reversed RX/RW mappings. One valid early CRC shortcut is recorded separately:
an unrelated pristine 673-byte app entry read need not precede rejection of
the selected corrupt 12-byte member. Exact corruption, archive closure and
absence of host acquisition remain mandatory.

The C source/header, build script and selected GNU library mapping implementation
remain byte-identical to merged `442d9eb`. Four C receipts and matching `nm`
logs retain API4, 29 selected exports, a 240-byte table and 264 verified headers.
Complete product ELF output has only `libm`, `libgcc_s` and `libc` dependencies
and no undefined `Py_*`/`_Py_*` imports. Regression inventories retain all ten
native ELF files and bind product/probe identities to the same checkpoint.
The product is byte-identical across its four captures, and the thin probe is
byte-identical across its five captures.

## Retention and replay

Root files retain 16 new modes; `regressions/` retains all 61 older modes.
Both include complete gzip traces, exact manifests, source metadata, outputs,
statuses, controls, commands, provenance and replay receipts. Large upstream
inputs, installations, executables and archives are identified by hashes rather
than copied. `source.sha256` covers 261 non-evidence files at `7a8e32c`;
documentation/evidence added after capture is outside that source snapshot.
Root `SHA256SUMS` covers every retained file except itself, and the nested
checksum file covers its subtree independently.

Five harnesses record the branch at capture. Four older harnesses lack that
receipt; their explicitly named `source-branch-at-retention.txt` records
retention time. Orchestration records branch/revision before and after every
group. All nine captures have the same clean implementation and empty source
status/diff; the initial sandbox socket failure is preserved separately and
produced no runtime trace.

For example, replay using retained metadata without the original archive:

```sh
python3 scripts/check-linux-python-install-host-source-app-trace.py \
  docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/stdlib.trace.txt.gz \
  --mode stdlib \
  --stdout-file docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/stdlib.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/stdlib.stderr.txt \
  --metadata-file docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/source-metadata.json \
  --archive-bytes 6779
```

Live checks additionally use `--archive-file` to bind metadata to actual bytes.
The retained replay/retention commands record all 77 checks. To repeat the
894-edit audit, copy `validation/product-trace-audit.py` to its original
`target/python-install-host-source-app-trace-audit.py` location in clean
`7a8e32c`, with the original capture/build directories cached, then use the
recorded command. Control audit scripts likewise use their recorded `target/`
locations. Workspace/protocol and orchestration logs remain in validation
subtrees, including the independently decoded complete stock provider audit.

## Scope

This supports one exact stock install-only GNU Linux arm64 host provider. It
keeps the full-source/bundled contracts, entry diagnostics and resource behavior.
It does not certify every installed file at runtime or expose arbitrary
site-packages/native modules. General uv/system installations, other runtime
versions/ABIs/platforms, wheels, native extension discovery, path-required
consumers, app arguments/`-m`, full tracebacks and workers remain open.
G0/G1/G2 remain open. See
[decision 0019](../../decisions/0019-install-only-host-python-source-apps.md).
