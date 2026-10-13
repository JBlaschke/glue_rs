# Python distribution metadata evidence — GNU Linux arm64, 2026-10-13

These optimized captures use clean implementation
`80c4b33698d7f9c6caa54f8c8afcc69ff6faa2ee` on
`codex/a7-python-distribution-metadata`, from merged `6cd8f96`.
The product uses linked Lua 5.4 plus `python-pbs`. Source revision, branch,
empty status/diff, commands, build provenance, image and cleanup receipts are
retained. Mac validation preceded the implementation commit on the same code;
all Linux execution and regression captures used the clean commit.

All **44 complete traces** pass both live checks and compressed replays:
nine metadata cases, six existing bundled source cases, thirteen full-host
source cases and sixteen install-only host source cases. These are fresh
regressions of the three affected source application routes; other historical
runtime routes were not recaptured in this increment. The original importer,
C bridge, API4 boundary and Linux/native loader files remain byte-identical
to the merged parent, recorded in [unchanged-mechanisms.json](unchanged-mechanisms.json).

## Observed cell and validation

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`
(repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`).
The GNU Linux arm64 cell uses kernel `7.1.4-200.fc44.aarch64`, glibc
`2.36-9+deb12u10`, 4,096-byte pages, Rust 1.88.0, GCC 12.2.0 and strace 6.1.
Runtime pins remain stock CPython 3.13.16 / PBS `20261009`, conventional GIL,
non-debug ABI. Runtime containers are offline, unprivileged (UID/GID 65534),
read-only and without workspace/build inputs; temporary paths are inaccessible
and Python environment variables point at unavailable paths.

| Validation | Result |
| --- | --- |
| Mac arm64 source workspace, Lua 5.4 / 5.5 | 441 / 442 Rust tests; Clippy with warnings denied; formatting passes |
| GNU Linux arm64 source workspace, Lua 5.4 / 5.5 | 441 / 442 Rust tests; Clippy with warnings denied |
| Each optimized GNU shared Python/probe build | 125 Rust tests; Clippy with warnings denied |
| Each optimized GNU product runner | 14 CLI tests; Clippy with warnings denied |
| Metadata adapter, Mac / pinned stock Linux Python | 32 / 32 tests |
| Unchanged importer and byte-entry protocols, stock Linux Python | 16 and 7 tests |
| Python trace-policy suite, Mac / pinned stock Linux Python | 227 / 227 tests, including 10 new metadata policy tests |
| Additional PBS inspector trace-policy suite, Mac | 17 tests |
| New product controls | 42 outcomes; independent payload/command checks plus six exact build checks |
| Independent hostile edits of actual metadata traces | All 189 reject, from nine passing baselines |
| Compressed trace replays | All 44 exit 0 |

[capture-summary.json](capture-summary.json) records each archive identity,
stdout/stderr identity, status, raw trace hash/size and replay result.
[independent-payload-audit.json](independent-payload-audit.json) verifies all
6,615 valid decoded members across the nine archives, all ten artifact hashes,
and the 36 inspect/verify/doctor/cat controls. Its independent script is retained.
The other three members deliberately fail CRC. The supplemental build audit
binds all six build reports to actual resource counts, uncompressed bytes,
archive lengths and hashes. [hostile-audit.json](hostile-audit.json) lists all
189 rejected mutations. Captured tool logs and traces are gzip-compressed
without changing their decompressed bytes.

## Outcomes and contract

The same archive application succeeds with bundled, full-host and install-only
host providers. It queries the normalized `Glue.Meta-Demo` version `1.2.3`,
metadata/requirements, loads a plugin returning `42`, maps import names to
distribution names, and reads RECORD files through immutable virtual objects.
Its seven RECORD rows include a quoted comma-containing asset name. Default
discovery works with an empty `sys.path`; explicit empty or unrelated Context
paths exclude the distribution. An absent distribution and both physical host
metadata lures remain invisible. Success output is exactly:

```text
glue python distribution metadata ok: version=1.2.3 plugin=42 files=7
```

Each provider also has two status-1 controls: an otherwise valid archive with
one RECORD path changed to `../escape.py`, and a single stored METADATA byte
flipped without changing its declared identity. Both reject before bundled
memfd creation or any host provider lookup. The independent audit verifies the
exact CSV cell and archive byte differences. Read-only commands preserve their
existing distinction: inspect/doctor validate declarations, cat verifies the
requested entry, verify catches CRC damage, and run also validates metadata
contents before provider acquisition. Build/doctor therefore admit the declared
bad-RECORD fixture until execution checks its contents.

The metadata helper is separately pinned at
`3e39d544468ddb014fb19c14347e4ea5ab85c01188213e556aff5f1ed3c3d4bd`.
Each metadata profile has its own build identity. Historical profile pins,
the trusted importer and provider inventories are unchanged. Portable tests
also enforce the original serialized manifest cap before removing the helper
to reuse legacy admission. The new trace policy privately reuses historical
policies and pins the additional observed metadata workload without widening
their accepted calls. It checks exact payload reads, provider exclusion for
rejections, virtual discovery, retained image/owner lifetimes and forbidden
fallback, extraction, process and network activity.

Both actual metadata host trees contain documented `Glue.Meta-Demo` version
`999` and `Glue-Metadata-Physical-Lure` version `99` additions. Their provenance
records identify those bytes; the runtime volume remains read-only until
cleanup. The metadata harness does not independently audit the entire stock
installation after execution. The unchanged install-only regression harness
does perform its complete ten-provider-tree post-runtime audit, retained under
`regression-install-host/`. These are distinct evidence claims.

This increment supports bounded source-only `.dist-info` applications on the
observed pinned GNU Linux arm64 cell. Generic venv/wheel ingestion, dependency
resolution, editable installs, general native packages, other runtime versions
and platforms remain separate work. It does not close G3/G4/G5 or implement
Node. See [decision 0021](../../decisions/0021-python-distribution-metadata.md).

## Replay

From the repository root, a retained metadata trace can be replayed using the
archive size in `source-metadata.json`; original large runtime archives are
identified by hashes rather than checked in:

```sh
python3 scripts/check-linux-python-metadata-trace.py \
  docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13/host.trace.txt.gz \
  --mode host --archive-bytes 13481 \
  --stdout-file docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13/host.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13/host.stderr.txt \
  --metadata-file docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13/source-metadata.json
python3 scripts/test_linux_python_metadata_trace.py --audit-capture \
  docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13 \
  target/python-metadata-retained-hostile-audit.json
```

Each regression subdirectory retains its historical commands, source metadata,
complete compressed traces and checker outputs. `SHA256SUMS` covers every
retained file except itself. Verify it from this directory with `shasum -a 256 -c SHA256SUMS`.
