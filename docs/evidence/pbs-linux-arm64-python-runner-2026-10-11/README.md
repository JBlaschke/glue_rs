# Controlled PBS Python launcher evidence — GNU Linux arm64, 2026-10-11

These fresh optimized captures use clean implementation
`32a9562c6e0e60da458e874d29c0e1bd17af098b` on
`codex/a7-python-runner-profile`, from merged `f92ac34`. The product launcher
uses default linked Lua 5.4 plus `python-pbs`; the historical probe shares the
same `glue-runtime-python` crate through `pbs-bootstrap`.

The nine product invocations are ordinary `glue run APP.glue` commands. They
cover the exact bundled and explicit-host source/resource profiles, four
independent runtime/native provider combinations, archived native corruption,
and missing/altered explicit host images. The 33 regression invocations cover
registered native initialization (11), host archive imports (7), bundled archive
imports (3), frozen startup (4) and installed-host startup (8). All **42 complete
traces** pass their strict live checks and independent compressed-file replays
from this implementation. Historical trace policies remain unchanged.

## Observed cell and validation

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`
(repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`).
The observed cell uses GNU Linux arm64, kernel `7.1.4-200.fc44.aarch64`,
glibc `2.36-9+deb12u10`, 4,096-byte pages, Rust 1.88.0, GCC 12.2.0 and strace
6.1. The stock runtime remains CPython 3.13.16 / PBS `20261009`, conventional
GIL, non-debug. Full input, install-only, frozen bundle, host sources and native
image identities are retained in the pins/provenance and summaries.

| Validation | Result |
| --- | --- |
| Mac arm64 source workspace, Lua 5.4 / 5.5 | 350 / 351 Rust tests; all-target Clippy with warnings denied |
| Mac arm64 Python-enabled workspace | 350 Rust tests; all-target Clippy with warnings denied; execution remains unsupported on Mac |
| GNU Linux arm64 source workspace, Lua 5.4 / 5.5 | 350 / 351 Rust tests; all-target Clippy with warnings denied |
| Every optimized GNU shared Python/probe build | 73 Rust tests; all-target Clippy with warnings denied |
| Optimized GNU product runner | 14 CLI tests; all-target Clippy with warnings denied |
| Trace-policy suite, Mac / pinned stock Linux Python | 209 / 209 tests |
| Importer protocol, Mac / pinned stock Linux Python | 16 / 16 tests |
| Product CLI controls | All 30 exact inspect/verify/doctor/cat results agree with archive bytes and expected statuses |
| Independent actual-product hostile trace edits | All 185 reject with `TraceError`, from nine passing clean baselines |
| Compressed trace replays | All 42 exit 0 |

The initial Mac validation was interrupted while parallel vendoring refreshed
the dependency cache. Successful final checks use an isolated Cargo home and
stable vendored inputs; the two interrupted logs and final commands are retained
in `validation/`. No implementation changes were needed for those retries.

## Product results and identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Product release `glue` | 3,333,032 | `579f9d9d0a59d8e10ca8042e887cf23a560a41e0bfc1d5a6640aa759be2bc9fd` |
| Shared thin regression probe | 3,192,168 | `96727f7b9358732cfcf0c8b31161fcd0e929d0afe9ce1b104fbcafa13ec8a890` |
| bundled-imports archive | 83,092,494 | `cb4c6365600e29efd3066ec9f233f2f1467a7a13f3438c4f12defbe4bb9f9520` |
| host-imports archive | 13,932 | `7c40a384de3af8855fa60c059c96a9de16477167153b5abe0eafd613db752682` |
| bundled-archived archive | 83,438,354 | `db387750e1d79b9e16d6ec3553ce19e867b3272115c4232994e2925440542a97` |
| bundled-host archive | 83,094,831 | `aab881196962c0fb25d4a0874baccfc0e2049f2ab344f6cd70596f347bc984d5` |
| host-archived archive | 359,787 | `7c8d5f07bdef95c89ba5dd38cfc85a19bdefcc29b8e2875a34d4197bc0a1ec00` |
| host-host archive | 16,264 | `524ec61d5705cf3276cd9fb52e6f5c4ae428e0a3de15067347b9e90b835091c4` |

| Product mode | Exit | Stdout / stderr bytes | Trace records |
| --- | ---: | ---: | ---: |
| `bundled-imports` | 0 | 100 / 0 | 33,514 |
| `host-imports` | 0 | 100 / 0 | 5,714 |
| `bundled-archived` | 0 | 169 / 0 | 33,685 |
| `bundled-host` | 0 | 169 / 0 | 33,799 |
| `host-archived` | 0 | 169 / 0 | 5,880 |
| `host-host` | 0 | 169 / 0 | 5,989 |
| `corrupt-native` | 1 | 0 / 79 | 26,583 |
| `missing-host-image` | 1 | 0 / 141 | 33,378 |
| `wrong-host-image` | 1 | 0 / 111 | 33,430 |

Source-only successes write the existing 100-byte conformance line. Native
successes add the 69-byte line matching the independent stock public-API
registration driver. Negative product controls write no stdout and use the
ordinary `glue:` diagnostic prefix. The thin probe is byte-identical across all
five regression captures, with a separate identity from the product executable.

The product's complete `readelf -W` listing shows only `libm`, `libgcc_s` and
`libc` dependencies and no undefined `Py_*`/`_Py_*` symbols. All four product
C provenance receipts identify shared boundary API4, 29 selected public
exports and a 240-byte table; `nm` logs show no direct Python API imports.
Ten exact native ELF files are retained across product/regression directories,
with five images totaling 341,400 bytes in each capture. Their declared hashes,
manifest inventories, inspected load ranges, dependencies and initializer
records are cross-checked during retention.

## Runtime and trace contract

Each runtime container is offline, unprivileged, read-only, without a workspace
mount. Its working directory is empty, temporary paths are unavailable, and
Python environment variables are poisoned. Producer tools, headers, preparers
and build intermediates are removed before tracing. Explicit host installations
and native files remain immutable read-only prerequisites.

The product checker admits exactly one launcher `execve`, exact inherited
output streams and diagnostic bytes, and one bounded `uname` after metadata
admission. Retained readiness byte counts, cursor and read-range digest are
independently derived from the actual canonical archive layout. Missing,
repeated or reordered readiness queries reject. The wrapper then delegates
runtime acquisition, source imports, native mapping and finalization events to
independent instances of the unchanged earlier policies.

The opened archive transfers directly to execution. Its selected profile limits
are rechecked without I/O before payload reads; all required resources verify
before closure and explicit host lookup. Complete traces check archive byte
coverage, descriptor lifetimes, full memfd writes and all required seals before
mapping, private provider ownership, exact output/exit, and absence of payload
filesystem mutation, extra processes or undeclared source fallback. Failed
forbidden attempts also reject. Corruption summaries prove that exactly one
stored dependency/source byte changed in each corresponding control.

Bundled source projection retains 2,174 pinned stdlib `.py` files totaling
39,158,056 bytes. The host source/resource archive has 18 entries and no stdlib
payload; its controlled installation verifies six startup and 63 supplemental
sources totaling 1,434,587 bytes, plus required absent caches. The existing
archive/native callbacks remain live through real `Py_FinalizeEx`.

## Retention and replay

`capture-summary.json`, per-profile `fixture-summary.json`, `trace-summary.json`,
exact manifests, commands, raw stdout/stderr/statuses, read-only controls,
provenance, native ELF files and gzip traces are retained. Large upstream
archives, runtime archives and executables are identified by hashes rather than
copied. `source.sha256` covers 220 non-evidence source files at the implementation
commit. `SHA256SUMS` covers every retained file except itself.

Product and native-regression branches were recorded during capture. The four
older harnesses did not emit branch receipts; their branch names are explicitly
recorded at retention time in `source-branch-at-retention.txt`. All six original
capture receipts independently record the same clean commit and empty source
diffs/statuses.

For example, replay the archived native product trace using the retained layout
and image metadata, without the large archive:

```sh
python3 scripts/check-linux-python-runner-trace.py \
  docs/evidence/pbs-linux-arm64-python-runner-2026-10-11/bundled-archived.trace.txt.gz \
  --mode bundled-archived \
  --stdout-file docs/evidence/pbs-linux-arm64-python-runner-2026-10-11/bundled-archived.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-runner-2026-10-11/bundled-archived.stderr.txt \
  --archive-bytes 83438354 \
  --native-metadata-file docs/evidence/pbs-linux-arm64-python-runner-2026-10-11/native-metadata.json
```

Corrupt-native replay also supplies the retained `corrupt_native.data_offset`.
`validation/retain-evidence.py` records all 42 replay commands and identity checks;
`validation/product-trace-audit.py` and its commands/result JSON retain the
185-edit audit. To repeat that audit, copy the retained script to
`target/python-runner-trace-audit.py` in a clean `32a9562` checkout, with the
original capture/build directories still cached, then use the recorded command.
The script resolves checker paths from that original location and requires
the checker checkout to match the clean capture commit.

## Scope

This is controlled product integration for the exact existing declaration
registry, on one observed cell. `doctor` checks declarations and build/target
prerequisites without loading Python or inspecting host providers; `run` checks
selected archive bounds, contents and explicit-host prerequisites. The default
Lua execution limit stays 64 MiB while inspection admits the 80 MiB member bound
needed by the pinned Python library.

Native hashes identify admitted images; they do not establish safety of arbitrary
C. Host descriptors/hashing do not freeze mutable backing files or bind Python's
later pathname reads. General application/stdlib admission, wheels, extension
file discovery, version selection, additional creation/free conformance,
workers, other Python ABIs/platforms and declared minimum-version acceptance
remain open. G0/G1/G2 remain open. See
[decision 0016](../../decisions/0016-controlled-python-runner.md).
