# Python archive imports and resources — GNU Linux arm64

Unchanged stock CPython 3.13.16 / PBS `20261009` imported app/stdlib source,
regular packages and one-portion namespaces from verified archive memory on
2026-10-10. Actual `importlib.resources` supplied immutable binary/text streams.
The ordinary-loader comparison agreed, and all three complete import traces
passed after removing the installed producer, stdlib, headers and library files.
Four frozen-startup and eight installed-host regression traces also passed.

All three optimized captures used clean implementation
`94da8de499cf860f7d06fb9fec2b51eae46d0132` on
`codex/a7-python-archive-imports`, based on merged `29b3f76`. Every captured
`source-status.txt` and `source-diff.patch` is empty. `source.sha256` identifies
tracked source at that checkpoint, excluding evidence directories. This following
commit adds the retained evidence and documentation links.

## Observed cell and identities

The immutable image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, with
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
The cell uses Rust 1.88.0, Debian bookworm, Linux `7.1.4-200.fc44.aarch64`,
glibc `2.36-9+deb12u10`, GCC 12.2.0, strace 6.1, 4,096-byte pages and
`vm.memfd_noexec=0`. See `environment.txt` and `image-inspect.json`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Release launcher, identical in all three captures | 2,854,992 | `0f69f92f90de178f57c04574daa215942b55499e72685f18591a6bc294b7a3b4` |
| Successful import archive | 83,092,207 | `6116aa873b97c38a19c3d6ee2384c2cd32bca952e02a2fd2df613ea6ee788283` |
| Corrupt-source control archive | 83,092,207 | `1bfaa4cecf608e1b8d6943ba55c23292a70509c2cd9520cbe3fdd30cf1e4f418` |
| Unchanged stock shared library | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |
| Matching-producer startup bundle | 139,523 | `6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7` |

The archive declares 2,194 resources, including all 2,174 regular `.py` files
under the pinned installed stdlib: 39,158,056 source bytes. This explicit
source-only projection includes development/site-packages sources, without
adding site-packages to search paths or claiming complete installation support.
The exact inventory is [checked in](../../../fixtures/python-imports/stdlib-pins.json)
and derives from the independently retained
[full-PBS inventory](../pbs-linux-arm64-inspection-2026-10-09/inputs/linux-aarch64-full-inventory.json.gz).
`fixture-summary.json` records its identity. `manifests/` retains exact canonical
manifest bytes, checked against the locator's hash and source inventory.

`upstream-pins.json` retains the independently pinned input URLs, sizes and
hashes. `freeze-provenance.json` records the matching stock build-time producer,
six selected startup sources and 264 verified headers totaling 1,830,329 bytes.
`build-provenance/` records C boundary/API revision 3, 28 acquired public Python
exports, verified-header identity and no linked Python symbols. No interpreter
patch is applied.

## Runtime observations

Preparation verifies the pinned upstream input and every source/app/helper
identity. Runtime admission eagerly verifies and decodes source/resources,
then closes the archive before loading the selected library. Rust owns the
immutable module/resource index; C copies and releases request replies before
further Python API calls. The trusted importer runs before the application.

The runtime launcher and two archives are relocated below a path containing
spaces. The separate container runs UID/GID 65534 from an empty directory with
read-only root/build mounts, no workspace mount or network, unavailable
HOME/TMPDIR, mode-000 `/tmp` and poisoned Python environment variables. The outer
harness writes capture files; the traced launcher writes only to inherited
stdout/stderr. `commands.sh`, `runtime-identity.txt`, `runtime-mounts.txt` and
`post-removal-files.txt` retain the setup and remaining files.

| Mode | Exit | Stdout / stderr bytes | Trace records | Observation |
| --- | ---: | ---: | ---: | --- |
| Success | 0 | 100 / 0 | 33,503 | Archive imports/resources and finalization checks pass |
| App error | 1 | 100 / 66 | 33,517 | Expected output followed by the exact controlled error |
| Corrupt source | 1 | 0 / 99 | 28,700 | Exact CRC rejection before any memfd/Python load |

Successful output is exactly:

```text
PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42
```

The app checks caching/reload, relative/circular imports, failed-import cleanup,
namespace resources, source encoding cookies, ignored bytecode, virtual metadata,
binary/Unicode assets, independent stream positions and read-only operations.
Actual stock `importlib.resources` is imported from archive source. Its `as_file`
and legacy `path` helpers reject archive files/directories before temporary-file
attempts; path coercion and traversal reject. An `atexit` callback reads binary
and text resources during actual Python finalization, while the Rust context
remains live. It adds no output; any callback failure would violate empty stderr.

The intentional syntax-error import preserves its virtual filename, source text
and offsets. Stock CPython attempts source-file lookup for ordinary virtual or
angle-bracket compile filenames. The importer uses an unpaired high-surrogate
sentinel that this UTF-8 filesystem encoder rejects before an OS lookup, then
restores virtual filenames recursively through public `code.replace` and in
syntax-error fields. The final traces contain no source-open attempt for either
virtual origins or that sentinel. This compiler-diagnostic observation is scoped
to this provider/encoding cell; general traceback/linecache and warning behavior
remains outside the fixture.

The corrupt archive differs at exactly byte 341164, the first byte of the stored
104-byte `app/python/glue_demo/__init__.py`. Its manifest and expected CRC/hash
remain unchanged. `fixture-summary.json` records original/corrupt source hashes
and the selected data offset; retention compared the complete archives to verify
that this was their sole difference.

Each trace uses `strace -f -s 256 -yy -e trace=all`. The strict import policy
requires archive coverage/closure before image creation, complete library
population, all four seals and their verification, one read-only descriptor
alias, both exact private stock-library mappings and pinned image lifetime.
Output publication requires the initialized import phase. Corrupt admission
requires the locator, archive-size observation, exact selected corrupt source
read and archive closure before the diagnostic, without any memfd attempt.

Only the observed OS-loader/startup reads and bounded allocation/entropy/query
operations are admitted. Unknown calls, failed or successful filesystem mutation,
source fallback, extra processes/threads, anonymous executable mappings and W+X
fail the checker. This trusted-fixture evidence policy is not a runtime sandbox.

`trace-summary.json` records raw/gzip sizes and hashes, record counts and PIDs.
All 15 retained deterministic-gzip traces were decompressed, hash-checked and
independently replayed through their respective strict policies. Replay logs
and exit statuses are retained beside each trace.

## Regression and validation

[Frozen startup](frozen-regression/README.md) passes all four existing modes with
108-byte successful output after removing the producer/stdlib/library. The
[installed-host regression](host-regression/README.md) passes all eight existing
modes with 111-byte successful output and its explicit read-only installation.
These captures prove that the shared C/API changes preserve earlier startup
behavior. They do not establish archive app imports with a host provider.

Mac and GNU Linux source workspaces passed 316 tests for Lua 5.4 and 317 for Lua
5.5, plus all-target Clippy with warnings denied. These assembly logs include
40 portable Python bundle/profile/index tests. Each of the three fresh clean
Linux builds passed 45 opt-in release tests, Clippy and compilation, including C
callback ownership and Rust panic-payload destructor controls. All 141 Python
policy tests passed, including 29 adversarial import-policy methods. Independent
review additionally rejected ten hostile mutations of actual import traces.

The importer passed 16 fake-callback protocol tests on the observed Mac Python
3.15.0 and exact stock Linux Python 3.13.16. Those tests are separate from actual
runtime acquisition. Mac opt-in compilation passed; execution returned status 2
before opening a missing archive. `validation/` retains these test, Clippy,
environment and unsupported-target logs. `linux-workspace-commands.sh` records
the offline source-workspace checks. All fresh fixture commands and build logs
are retained in their respective capture directories.

## Reproduction

Provision the cached inputs as described in
[the PBS fixture](../../../fixtures/python-pbs/README.md), use the recorded image
and Rust toolchain, then run from the repository root with new output directories:

```sh
sh fixtures/python-imports/run-linux.sh target/python-imports-recapture \
  target/python-imports-recapture-build
sh fixtures/python-bootstrap/run-linux.sh target/python-imports-frozen-recapture \
  target/python-imports-frozen-recapture-build
sh fixtures/python-host/run-linux.sh target/python-imports-host-recapture \
  target/python-imports-host-recapture-build
```

Replay all retained traces without the large runtime/build outputs:

```sh
python3 - <<'PY'
import json, pathlib, subprocess, sys
p = pathlib.Path('docs/evidence/pbs-linux-arm64-python-imports-2026-10-10')
for directory, checker in [('', 'import'), ('frozen-regression', 'bootstrap'), ('host-regression', 'host')]:
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

`SHA256SUMS` covers every retained file except itself, including both regressions.
It detects corruption and does not authenticate the author.

## Limits

This is a controlled bundled source/resource adapter for one optimized GNU Linux
arm64 cell, using trusted pinned artifacts and eager verified memory. Full
stdlib/package compatibility, general diagnostic source consumers, product Python
execution/acquisition, host-provider archive imports, native extension loading,
other versions/platforms and release acceptance remain open. G0/G1/G2 remain open.
See [the decision](../../decisions/0013-python-archive-source-resources.md).
