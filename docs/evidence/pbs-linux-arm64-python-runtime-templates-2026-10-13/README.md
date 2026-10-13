# Python runtime templates — GNU Linux arm64 / Mac preparation

The clean product capture uses implementation `3d15bf9a5a8d300e17afe45dd00d2d83a930f5e9`
on `codex/a7-python-runtime-templates`, based on merged `c0ddaa4`.
`glue python-template` prepares the exact bundled, full-host and install-only-host
metadata profiles for direct use by `glue build-python`. See
[decision 0023](../../decisions/0023-python-runtime-templates.md) and the
[fixture](../../../fixtures/python-runtime-templates/README.md).

Bundled preparation verifies the complete pinned full PBS artifact and retained
frozen startup bundle, then preserves the stock library and 2,174 source files.
The bundled template contains 2,179 resources / 112,880,057 uncompressed bytes.
Host preparation owns only two helpers and the placeholder: three resources /
18,510 bytes. Host declarations do not inspect the prefix and explicitly report
unverified prerequisites. Installation/version discovery and startup generation
remain separate work.

## Observed controls

Both the clean Mac capture and GNU capture pass eight template generations,
45 hostile controls and three builds from the genuine offline-installed fixture.
Repeated reports, manifests, provenance and every owned resource are identical.
The independent oracle checks exact provider declarations, source/cache pins,
helpers, frozen/library bytes, producer facts, publication protection and
placeholder replacement. Generated resource trees and archives are removed
after their independent checks; retained manifests, full resource inventories,
reports, commands, statuses and input identities record those observations.
See [GNU controls](template-controls/audit.json) and
[Mac controls](macos/template-controls/audit.json).

Three separate template process/file/network traces show one launcher execution,
no interpreter/child execution or network calls, and no target-host lookup.
The initial clean harness ran thirteen oracle tests. The strengthened checker
also covers working-directory changes, fd-relative paths, encoded/normalized
paths, target library/interpreter lookup, extra PIDs and incomplete boundaries.
All twenty-one strengthened tests pass on Mac and stock GNU Python, and all three
preparation traces pass. Follow-up checker commit
`525da1994b6735db10b2aba3abece3946daec52c` changes only the fixture oracle, its
tests and fixture documentation; product code is unchanged. See
[checker attribution](oracle-strengthening.json). Its later checks and compressed
replays are retained separately from the original capture. Bundled publication
may exclusively create the declared library output;
reading or inspecting a target library is rejected by the process checker.

The existing installed-input fixture still passes both input modes and all
30 hostile controls. Three build process traces each contain exactly one builder
execution and exit, with no child or input-interpreter execution. Independent
[product checks](product-audit.json) verify all 27 product commands, 4,427 valid
archive members, exact installed bytes and transformation reports, plus three
intentional single-byte CRC failures. Every one of the six emitted archive
identities matches the preceding clean venv increment; see
[archive equivalence](prior-archive-equivalence.json).

| Runtime mode | Exit | Observation |
| --- | --- | --- |
| bundled | 0 | Archive packages, metadata/plugins and resources execute |
| host | 0 | Same application against the exact full source installation |
| install-host | 0 | Same application against the exact install-only inventory |
| bundled-corrupt-metadata | 1 | CRC failure precedes bundled acquisition |
| host-corrupt-metadata | 1 | CRC failure precedes host inspection/acquisition |
| install-host-corrupt-metadata | 1 | CRC failure precedes install-only inspection/acquisition |

All six complete runtime traces pass the unchanged installed-package policy and
replay from the retained gzip bytes. All 126 hostile actual-trace mutations reject;
the retained replay reproduces the audit inventory. No runtime policy was widened.
The importer/metadata helper, C boundary, runtime profile bodies and GNU loading
files are byte-identical to merged main; see [unchanged runtime](unchanged-runtime.json).

## Cell and validation

The pinned offline Podman image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`,
with kernel `7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2,
strace 6.1 and 4 KiB pages. The actual GNU launcher is built with Rust 1.88.0
and verified CPython 3.13.16 headers. PBS release `20261009` full and install-only
artifacts have their existing complete identities. Runtime execution uses uid/gid
65534, read-only runtime storage, no network and inaccessible temporary/home
locations. The producer, headers and staging tree are removed before execution.
Stock host installation and pip invocation belong only to fixture setup.

Mac and GNU source workspaces pass 460/461 tests for Lua 5.4/5.5 with Clippy.
The Mac packaging workspace passes 482. Optimized GNU suites pass 135 Python/probe,
41 packaging and 19 CLI tests, with Clippy. Metadata/importer/entry protocols pass
32/16/7. The Python runtime-policy suite passes 235 tests on Mac and stock GNU
Python. Format is clean. Pre-commit workspace logs are explicitly bound to the
identical committed code; clean template capture receipts identify the source and
binary. Follow-up checker validation is distinguished from product capture.

## Replay

Complete runtime traces, template traces and build process traces are retained
as gzip with no omitted records. `source-metadata.json`, `capture-summary.json`
and `artifacts.sha256` identify the observed archives/launcher. The large stock
payload archives and target interpreter are not duplicated in Git.

```sh
evidence=docs/evidence/pbs-linux-arm64-python-runtime-templates-2026-10-13
python3 scripts/check-linux-python-venv-trace.py "$evidence/bundled.trace.txt.gz" \
  --mode bundled --stdout-file "$evidence/bundled.stdout.txt" \
  --stderr-file "$evidence/bundled.stderr.txt" \
  --metadata-file "$evidence/source-metadata.json" --archive-bytes 83093626
python3 scripts/test_linux_python_venv_trace.py --audit-capture \
  "$evidence" target/template-hostile-replay.json
python3 fixtures/python-runtime-templates/test_templates.py \
  --audit-process-trace "$evidence/host.template-process.trace.txt.gz" \
  --program /build-target/release/glue --host-prefix '/build-target/host Python metadata'
```

With matching exported archives, the retained `product-audit.py` can independently
verify this complete retained capture. `SHA256SUMS` covers all retained
files except itself. This establishes portable template processing and the exact
controlled GNU runtime cell. Mac execution, other runtime versions/providers,
native packages, uv installations, dependency solving and wider platforms remain
unimplemented or require separate evidence. G0/G1/G2/G3 remain open.
