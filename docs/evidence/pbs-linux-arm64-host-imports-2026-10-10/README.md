# Python archive imports with an installed host — GNU Linux arm64

Unchanged stock CPython 3.13.16 / PBS `20261009` imported archive application
source, regular packages and one-portion namespaces using its explicit installed
stdlib on 2026-10-10. Actual installed `importlib.resources` supplied immutable
binary/text streams from verified archive memory. The shared application agreed
with the ordinary-loader bundled comparison, and all seven complete host traces
passed in the separate unprivileged, offline, read-only runtime cell. Three
bundled-import, four frozen-startup and eight installed-host startup regression
traces also passed, giving 22 complete traces across the four profiles.

The host capture used clean implementation
`9aababab78156f84628128060b64f51906bde5fe` on
`codex/a7-host-python-archive-imports`, based on merged
`f99bb51cf1c48176460c83b413a53e91509a3821`. Its captured `source-status.txt` and
`source-diff.patch` are empty. All three regression captures use the same clean
checkpoint with empty status/diff.
`source.sha256` identifies tracked source at that checkpoint, excluding evidence
directories. This following commit adds retained evidence and documentation links.

## Observed cell and identities

The immutable image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, with
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
The cell uses Rust 1.88.0, Debian bookworm, Linux `7.1.4-200.fc44.aarch64`,
glibc `2.36-9+deb12u10`, GCC 12.2.0, strace 6.1 and 4,096-byte pages.
See `environment.txt` and `image-inspect.json`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Release launcher, identical in all four captures | 3,266,864 | `bc0d43be649fc4eb9b0c15720baad5e77556b37f2369ea9e68be10a82f3b27c5` |
| Successful host-import archive | 13,932 | `7c40a384de3af8855fa60c059c96a9de16477167153b5abe0eafd613db752682` |
| Corrupt-source control archive | 13,932 | `3ef231cbfa97bbdf50b1e38b5aa693824478ff15d74d3d5ed0b7596774b1024e` |
| Unchanged installed shared library | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |
| Matching-producer startup bundle, build input only | 139,523 | `6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7` |

The host archive declares 18 app/helper/resource entries totaling 23,243
uncompressed bytes. No runtime library, frozen startup bundle or stdlib source
is embedded. `fixture-summary.json` records every prepared archive's size/hash,
including the different explicit prefixes of the invalid-host controls.
`manifests/` retains their exact canonical manifest bytes, checked against the
locator hash. App, importer and asset bytes are shared with the bundled fixture.

The installed dependency closure has 69 pinned sources totaling 1,434,587 bytes:
the existing six startup sources plus
[63 supplemental sources](../../../fixtures/python-host-imports/stdlib-import-pins.json)
totaling 1,372,061 bytes. The supplemental identities match the independently
[pinned complete source inventory](../../../fixtures/python-imports/stdlib-pins.json),
whose bytes have SHA-256
`d088049d2c9936748a1fd6139a9b5634ded6b64934b7df1b02638ab4aa3653c8`.
Preparation additionally checks those actual regular members against the
independently pinned full PBS input. The
[earlier full-PBS inventory](../pbs-linux-arm64-inspection-2026-10-09/inputs/linux-aarch64-full-inventory.json.gz)
retains upstream member identities. This is a reviewed fixture dependency
closure, not complete installed-stdlib or arbitrary-package certification.

`upstream-pins.json` retains pinned input URLs, sizes and hashes.
`freeze-provenance.json` records the unchanged stock build-time producer and
verified headers. `host-runtime-provenance.json` records the narrow installed
trees, their deliberate lures and invalid controls. `build-provenance/` records
the unchanged C boundary/API revision 3, its 28 acquired public Python exports,
verified-header identity and absence of linked Python symbols. The stock frozen
table remains untouched in host mode; no interpreter patch is applied.

## Runtime observations

Runtime admission verifies and decodes every app/helper/resource into immutable
memory, then closes the archive before any host prerequisite lookup. Rust
verifies the exact installed library and all 69 sources through bounded
no-follow reads, hashes, EOF checks and rewinds. All 12 relevant `__pycache__`
locations must be absent. The library loads through one verified read-only
descriptor alias, with the expected private OS-loader mappings and process-live
library ownership. Host mode creates no memfd and has no bundled-provider fallback.

C supplies isolated configuration, explicit matching prefixes, exactly one
installed stdlib search path and a virtual launcher identity. Environment, site,
user-site and bytecode-cache writes are disabled. Built-in and stock frozen
finders retain precedence; the shared archive finder precedes the installed path
finder. App names colliding with selected runtime/stdlib/bridge names reject at
index admission, including stock frozen aliases. The 96 built-in and 29 frozen
names are tied to the exact library; `validation/runtime-names-provenance.json`
and `validation/frozen-runtime-names.json` retain the independent ELF inventory identity and
matching-producer query. Archive-owned missing
descendants reject before path fallback, and archive namespaces retain one
portion. The installed module, namespace and bytecode lures remain unused.

The runtime launcher/archives and installed prefix contain spaces. A separate
container runs UID/GID 65534 from an empty directory with read-only root/build
mounts, no workspace mount or network, unavailable HOME/TMPDIR, mode-000 `/tmp`
and poisoned Python environment variables. Producer executables, headers and
Cargo intermediates have been removed. The outer harness writes capture files;
the traced launcher writes only to inherited stdout/stderr. `commands.sh`,
`runtime-identity.txt`, `runtime-mounts.txt` and `post-removal-files.txt` retain
the setup and remaining files.

The installation remains immutable and read-only throughout execution.
Retaining verified source/directory descriptors does not freeze mutable backing
bytes or bind Python's subsequent source-path lookups. A mutable installation
requires a separate policy and evidence. Disabling cache writes also permits
reads of existing bytecode: the exact stock CLI executed a planted unchecked-hash
cache in an isolated control. `validation/bytecode-read-control.*` retains its
script, commands, exact output and successful status. Cache absence is therefore
a prerequisite.

| Mode | Exit | Stdout / stderr bytes | Trace records | Observation |
| --- | ---: | ---: | ---: | --- |
| Success | 0 | 100 / 0 | 5,716 | Archive imports/resources and finalization checks pass |
| App error | 1 | 100 / 66 | 5,717 | Expected output followed by the exact controlled error |
| Corrupt source | 1 | 0 / 99 | 297 | Exact archive CRC rejection before any host lookup |
| Wrong library | 1 | 0 / 131 | 1,553 | Selected library hash rejects before mapping |
| Wrong import source | 1 | 0 / 141 | 2,433 | Changed supplemental source rejects before mapping |
| Missing import source | 1 | 0 / 164 | 2,426 | Missing supplemental source rejects before mapping |
| Cached import bytecode | 1 | 0 / 177 | 1,955 | Nested cache directory rejects before mapping |

Successful output is exactly:

```text
PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42
```

The app checks caching/reload, relative/circular imports, failed-import cleanup,
namespace resources, source encoding cookies, ignored app bytecode, virtual
metadata, binary/Unicode assets, independent stream positions and read-only
operations. Actual stock `importlib.resources` is imported from its verified
installed source. Its `as_file` and legacy `path` helpers reject archive
files/directories before temporary-file attempts; path coercion and traversal
reject. The read-only registration applies to archive objects rather than
turning ordinary host I/O into an archive filesystem.

An `atexit` callback reads binary and text archive resources during actual
Python finalization, while the Rust callback context remains live. It prints
nothing; a callback failure would violate the success mode's empty stderr or
the app-error mode's exact diagnostic. Verified host source/directory owners
and host-path buffers remain live through the synchronous C call and finalization.
C copies each callback reply and releases its Rust-owned buffer before further
Python API calls; no Python object crosses Rust.

The intentional syntax-error import preserves its virtual filename, source text
and offsets. Stock CPython attempts source-file lookup for ordinary virtual or
angle-bracket compile filenames. The shared importer uses an unpaired
high-surrogate sentinel that the configured UTF-8/surrogateescape filesystem
encoder rejects before an OS lookup, then restores virtual filenames recursively
through public `code.replace` and in syntax-error fields. The traces contain no
source-open attempt for either virtual origins or the sentinel. This observation
is scoped to the pinned provider/encoding cell; general traceback/linecache and
compiler-warning consumers remain outside the fixture.

The corrupt archive differs at exactly byte 6,235, the first byte of the stored
104-byte `app/python/glue_demo/__init__.py`. Its manifest and expected CRC/hash
remain unchanged. `fixture-summary.json` records the original/corrupt source
hashes and data offset; retention compares the complete archives to confirm the
single-byte difference.

Each trace uses `strace -f -s 256 -yy -e trace=all`. The strict host-import policy
requires complete archive admission/closure before host access, all 69 pinned
source reads and cache prerequisites before image loading, both exact private
library mappings and the selected installed-source import closure. Python
reopens 67 installed sources during the successful/app-error runs; `codecs.py`
and `encodings/ascii.py` are preverified but not reopened by this workload.
Directory probes/enumerations and source read sizes/EOF are checked separately
from pre-initialization hashing. Invalid prerequisites require the exact failed
validation phase, closed inputs, diagnostic and exit without image loading.

Only observed OS-loader/startup reads and bounded allocation/entropy/query
operations are admitted. Unknown calls, successful or failed filesystem mutation,
archive-source fallback, extra processes/threads, anonymous executable mappings,
W+X and provider substitution fail the checker. The trusted-fixture evidence
policy is not a runtime sandbox or a general import policy.

`trace-summary.json` records raw/gzip sizes and hashes, record counts and PIDs.
All 22 deterministic-gzip traces were decompressed, raw-hash checked and
independently replayed with zero exit status. Replay logs and statuses are
retained beside each trace.

## Regression and validation

The [bundled import regression](bundled-import-regression/README.md) repeats all
three modes with 100-byte successful output after producer/stdlib/library/header
removal. The [frozen-startup regression](frozen-regression/README.md) repeats all
four existing modes with 108-byte successful output. The
[installed-host startup regression](host-startup-regression/README.md) repeats
all eight existing modes with 111-byte successful output and its explicit
read-only installation. All captures pass their respective strict policies.
Their respective READMEs and summaries
retain identities, counts and limits. These preserve the earlier controlled
profiles alongside the new host archive-import observation.

Working-assembly Mac and GNU Linux source workspaces passed 327 tests for Lua
5.4 and 328 for Lua 5.5, plus all-target Clippy with warnings denied. These logs
include 51 portable Python bundle/profile/index/host tests. Each of the four fresh clean
Linux builds passed 56 opt-in release tests, Clippy and compilation, retaining
C callback ownership and Rust panic-payload destructor controls. All 161 Python
policy tests passed, including 20 new host-import methods. Independent review
rejected 29 hostile mutations of actual host-import traces.
`validation/host-policy-mutation-review.txt` records the clean source/checker
identities, actual trace hashes and all 29 rejected mutations. `source.sha256`
records 195 tracked source identities; every validation log is retained.

The importer passed 16 fake-callback protocol tests on the observed Mac Python
3.15.0 and exact stock Linux Python 3.13.16. They are separate from actual host
runtime acquisition and do not execute the app's startup guards. Those guards
passed through the real C boundary in the clean ordinary-loader comparison and
host captures. `validation/` retains test, Clippy, environment and unsupported
target logs; `linux-workspace-commands.sh` records offline source-workspace checks.
Fresh fixture commands and build logs are retained with each capture.

## Reproduction

Provision cached inputs as described in
[the PBS fixture](../../../fixtures/python-pbs/README.md), use the recorded image
and Rust toolchain, then run from the repository root with new output directories:

```sh
sh fixtures/python-host-imports/run-linux.sh target/python-host-imports-recapture \
  target/python-host-imports-recapture-build
sh fixtures/python-imports/run-linux.sh target/python-host-imports-bundled-recapture \
  target/python-host-imports-bundled-recapture-build
sh fixtures/python-bootstrap/run-linux.sh target/python-host-imports-frozen-recapture \
  target/python-host-imports-frozen-recapture-build
sh fixtures/python-host/run-linux.sh target/python-host-imports-startup-recapture \
  target/python-host-imports-startup-recapture-build
```

Replay all four retained profiles without the large runtime/build outputs:

```sh
python3 - <<'PY'
import json, pathlib, subprocess, sys
p = pathlib.Path('docs/evidence/pbs-linux-arm64-host-imports-2026-10-10')
for directory, checker in [('', 'host-import'), ('bundled-import-regression', 'import'),
        ('frozen-regression', 'bootstrap'), ('host-startup-regression', 'host')]:
    q = p / directory
    summary = json.loads((q / 'fixture-summary.json').read_text())
    for mode, archive in summary['archives'].items():
        args = [sys.executable, 'scripts/check-linux-python-' + checker + '-trace.py',
            str(q / (mode + '.trace.txt.gz')), '--mode', mode,
            '--stdout-file', str(q / (mode + '.stdout.txt')),
            '--stderr-file', str(q / (mode + '.stderr.txt')),
            '--archive-bytes', str(archive['size'])]
        if mode == 'corrupt-source':
            args += ['--corrupt-source-offset', str(summary['corrupt_source']['data_offset'])]
        subprocess.run(args, check=True)
PY
```

`SHA256SUMS` covers every retained file except itself, including all three
regressions. It detects corruption and does not authenticate the author.

## Limits

This is a controlled shared archive source/resource adapter with bundled and
explicit installed-host observations for one optimized GNU Linux arm64 cell.
The host provider requires the exact pinned immutable installation and reviewed
dependency closure. Product Python execution/acquisition/discovery, arbitrary
packages, mutable installations, general diagnostic source consumers, native
extension initialization/loading, other versions/platforms and release acceptance
remain open. G0/G1/G2 remain open. See
[the host-import decision](../../decisions/0014-host-python-archive-imports.md).
