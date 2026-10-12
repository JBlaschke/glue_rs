# Explicit-host Python source application evidence — GNU Linux arm64, 2026-10-12

These optimized captures use clean implementation
`dd6274f9def358ce562ba229f79e14cc2fe6c818` on
`codex/a7-host-source-apps`, from merged `cb3cae4`. Captures and retention ran
on 2026-10-12. The product uses default linked Lua 5.4 plus `python-pbs`;
the historical thin probe shares `glue-runtime-python` through `pbs-bootstrap`.
The new harness's `development-opt-in.txt` is `false`.

All **61 complete traces** pass live checks and compressed-file replays:
13 new explicit-host source-app cases and 48 fresh regressions. The latter
cover bundled source apps (6), the original product registry (9), native
initialization (11), host archive imports (7), bundled archive imports (3),
frozen startup (4) and installed-host startup (8). Historical harnesses and
trace policies remain unchanged.

## Observed cell and validation

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`
(repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`).
The GNU Linux arm64 cell uses kernel `7.1.4-200.fc44.aarch64`,
glibc `2.36-9+deb12u10`, 4,096-byte pages, Rust 1.88.0, GCC 12.2.0 and
strace 6.1. Runtime pins remain stock CPython 3.13.16 / PBS `20261009`,
conventional GIL and non-debug mode.

| Validation | Result |
| --- | --- |
| Mac arm64 source workspace, Lua 5.4 / 5.5 | 381 / 382 Rust tests; all-target Clippy with warnings denied |
| Mac arm64 Python-enabled workspace | 381 Rust tests; all-target Clippy with warnings denied |
| GNU Linux arm64 source workspace, Lua 5.4 / 5.5 | 381 / 382 Rust tests; all-target Clippy with warnings denied |
| Every optimized GNU shared Python/probe build | 102 Rust tests; all-target Clippy with warnings denied |
| Optimized GNU product runner | 14 CLI tests; all-target Clippy with warnings denied |
| Trace-policy suite, Mac / pinned stock Linux Python | 261 / 261 tests |
| Existing importer and byte-entry protocols, both interpreters | 16 and 7 tests |
| Host source protocol, Mac / pinned stock Linux Python | 11 tests with 2 stock-only skips / all 11 pass |
| New host source-app product controls | All 51 exact controls agree |
| Bundled source-app / original product controls | All 34 / 30 exact controls agree |
| Independent hostile edits of actual new traces | All 567 reject, from 13 passing clean baselines |
| Compressed trace replays | All 61 exit 0 |

The 51 new controls include 12 successful builds, four read-only commands for
seven app/archive cases, six damaged-host doctor calls, three rejected build
declarations and two rejected doctor declarations. They bind expected results
to actual archive hashes, canonical manifests and entry bytes. Declaration
admission rejects before a missing input-root lookup or output creation.
Doctor reports declarations/build/target readiness without acquiring a host;
verify/run detect damaged archive bytes and run detects damaged host inputs.

## Artifacts and outcomes

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Product release `glue` | 3,397,400 | `bb391937bf7541bcf09f75efd2fedc9453a0c33170aea05f151d21a5b10b8555` |
| Shared thin regression probe | 3,188,392 | `f698b313193800b62e4d8a795345afe7f4a2d90a8c0ac61534d0bd2b737a099c` |
| minimal archive | 6,488 | `9924ef3c70138e9e11e68b2ee7b478b9592ad4b08850f2ac34b3e290f0f0d07e` |
| resources archive | 9,769 | `bd4e6ed9980c9f81510ff6671ad2f8126d0dd1367923e151105850a7b1e8f6a0` |
| stdlib archive | 6,755 | `b570820e3f0265f8b17b230fbd55160ff244acb78352b9f79982a083e53d6b35` |
| Installed `libpython3.13.so.1.0` | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |

| Mode | Exit | Stdout / stderr bytes | Trace records |
| --- | ---: | ---: | ---: |
| `minimal` | 0 | 50 / 0 | 24,624 |
| `resources` | 0 | 90 / 0 | 24,667 |
| `stdlib` | 0 | 76 / 0 | 24,576 |
| `app-error` | 1 | 0 / 43 | 24,617 |
| `syntax` | 1 | 0 / 42 | 24,576 |
| `nul` | 1 | 0 / 69 | 24,578 |
| `corrupt-source` | 1 | 0 / 70 | 149 |
| `missing-source` | 1 | 0 / 147 | 23,195 |
| `wrong-source` | 1 | 0 / 124 | 23,200 |
| `deep-cache` | 1 | 0 / 190 | 1,324 |
| `startup-native` | 1 | 0 / 182 | 1,479 |
| `startup-bytecode` | 1 | 0 / 155 | 1,490 |
| `missing-library` | 1 | 0 / 135 | 1,604 |

Five entry fixtures reuse the previous bundled applications and their
bounded byte-script diagnostics. The new stdlib entry exercises `fractions`,
`statistics`, XML, a source resource stream and finalization reads. Root host
source/bytecode/native lures and an unknown descendant below an owned stdlib
package cannot become default imports. Existing startup/frozen modules keep
stock metadata; later source modules use virtual `glue://` origins.

The host archives contain only the unchanged importer and app-owned files.
Their small sizes rely on an explicit installed prerequisite: the exact library
and all 2,174 pinned source files totaling 39,158,056 bytes. The install-only
distribution has 1,037 of these sources and lacks 1,137; the helper projects the
full inventory from independently verified full inputs. It performs this work
at build time without downloading or executing app code. Ordinary installation
contains no lures; those are enabled only for the fixture controls.

The C boundary source/header, build script and selected GNU library mapping
implementation remain byte-identical to merged `cb3cae4`. Host verification
and Linux route wiring add the new snapshot/provider path. Four C receipts and matching `nm` logs retain
API4, 29 selected exports, the 240-byte table and 264 verified headers. Complete
product `readelf -W` output shows only `libm`, `libgcc_s` and `libc` dependencies
and no undefined `Py_*`/`_Py_*` imports. Regression artifact inventories bind
the product, thin probe and ten native ELF files to this same checkpoint.
The product is byte-identical across its three captures, and the thin probe
is byte-identical across its five captures.

## Runtime and trace contract

Runtime containers are offline, unprivileged and read-only, without a workspace
mount. Working directories are empty, temporary paths unavailable and Python
environment variables poisoned. Producer/interpreter/header/preparer and staging/build inputs are removed
before tracing; image system tools remain installed. Installed library/startup paths remain
immutable read-only prerequisites throughout execution and finalization;
the mapped library backing file must remain immutable for process life.

Portable admission shares the bundled app policy and validates expanded host
paths before I/O. Execution verifies and closes the app archive before host
acquisition, then verifies the full source projection into owned bytes. All
202 derived cache locations must be absent. The selected encodings directory
is closed to extra entries; startup source/bytecode/native shadows reject
before Python initializes. Snapshot file descriptors close promptly, while
deduplicated directory and six startup source owners remain live through
finalization. At most 256 distinct directory owners are admitted, bounding
snapshot/startup ownership to 763 descriptors before existing process and
temporary loader descriptors.

The unchanged C bridge starts with installed encodings, then a trusted prelude
removes the default filesystem `PathFinder`, paths, hooks and importer cache
before the original source importer runs. Subsequent default source imports
and resource streams consume the immutable snapshot. Hashes and no-follow
descriptors do not freeze host library backing files or all startup pathname
lookups; the read-only installation prerequisite remains necessary.

The separate strict trace policy binds typed inventory, canonical layout,
provider/target, exact command, inherited streams and expected diagnostics/status.
Readiness occurs once after declaration metadata and before payload/host access.
It checks archive closure, complete source/library read coverage and EOF,
fresh no-follow metadata before each checked open, directory/cache/shadow checks,
the visible ELF prefix, alias header/fstat, RX/RW order, reserved image geometry,
guard/BSS/RELRO changes, alias closure and library image lifetime through exit.
The host route uses no memfd. Forbidden filesystem fallback, executable-memory
changes and process/thread creation attempts reject even when the syscall fails.

Initialized workloads retain the observed Python 2,496-byte entropy request,
one TID query and two bounded anonymous remaps. Successful output is checked
before retained owner closure; error cases combine the synchronous Rust/C
ownership contract with the observed phase ordering, since owners drop before
the outer error diagnostic. The evidence does not infer finalization solely
from an error-stream marker.

The hostile audit includes early closure of six startup descriptors before the
loader alias, early closure of all 262 retained leases before successful output,
reuse of stale path metadata and reversal of RX/RW mappings. All reject.
One separately recorded valid CRC-rejection shortcut remains accepted: an
early CRC rejection does not require complete unrelated payload coverage.
The edited trace omits the pristine 673-byte entry read that originally
preceded the selected corrupt 12-byte read. Exact corruption, archive closure
and absence of host acquisition remain required.

Tracing uses `-s 256`. Requested/returned byte counts establish complete read
coverage and visible bytes establish prefixes; truncated strings cannot
independently hash every source/library byte. Actual inputs, archive metadata
and runtime hashing supply complete identities under the immutable-host
prerequisite. This evidence claims the combined checks.

## Retention and replay

Root files retain the 13 new modes; `regressions/` retains all 48 older modes.
Both retain complete gzip traces, exact manifests, inventories, stdout/stderr,
statuses, controls, commands, provenance and replay receipts. Large upstream
inputs, executables and archives are identified by hashes rather than copied.
`source.sha256` identifies 251 non-evidence files at implementation `dd6274f`;
documentation/evidence changes after capture are outside that source snapshot.
Root `SHA256SUMS` covers every retained file except itself; the nested checksum
file also covers its subtree independently.

New host apps, bundled apps, original product and native-regression harnesses
recorded their branch during capture. Four older harnesses lack that receipt;
their explicitly named `source-branch-at-retention.txt` records retention time.
The orchestration records branch/revision around every group. All eight
captures record the same clean implementation and empty source status/diff.
Orchestration receipts preserve the interrupted start and clean resumed run.

For example, replay using retained metadata without the original archive:

```sh
python3 scripts/check-linux-python-host-source-app-trace.py \
  docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/stdlib.trace.txt.gz \
  --mode stdlib \
  --stdout-file docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/stdlib.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/stdlib.stderr.txt \
  --metadata-file docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/source-metadata.json \
  --archive-bytes 6755
```

Live checks additionally use `--archive-file` to bind metadata to actual bytes.
The retained replay commands and retention scripts record all 61 checks.
`validation/product-trace-audit.py`, its commands and result JSON retain the
567-edit audit and accepted CRC shortcut. To repeat it, copy the script to
`target/python-host-source-app-trace-audit-final.py` in clean `dd6274f` with the
original ignored capture/build directories cached, then use its recorded
command. The 51-, 34- and 30-control scripts also use their recorded `target/`
locations. Workspace/protocol logs and all orchestration receipts are retained
under the validation subtrees.

## Scope

This admits bounded source apps for one exact explicit-host GNU Linux arm64
provider. It pairs the earlier bundled provider while preserving its runtime
pins and source/resource behavior. It does not establish complete stdlib or
package compatibility: pinned site-packages and nonidentifier configuration
sources are not automatically import roots. Path-required consumers, wheels,
native extension discovery, runtime-version selection, app arguments/`-m`, full
tracebacks, workers, other Python ABIs/platforms and minimum-version acceptance
remain open. Trusted code can change import machinery and perform host I/O.
G0/G1/G2 remain open. See
[decision 0018](../../decisions/0018-host-python-source-apps.md).
