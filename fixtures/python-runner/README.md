# Optional pinned Python route through `glue`

This fixture exercises the ordinary product command, `glue run APP.glue`, with
the optional `python-pbs` feature. It uses the existing CPython 3.13.16 / PBS
`20261009` GNU Linux arm64 profiles: bundled archive imports, explicit host
archive imports, and the four registered-native provider combinations from
[the native fixture](../python-extensions/README.md). The selected runtime,
source inventories, bootstrap, application and native registration contracts
remain the reviewed experimental profiles. This does not enable general Python
discovery, arbitrary versions, wheels, mutable installations or other targets.
Default builds retain the linked Lua profile and the packaging-only resource
fixture.

With the [cached PBS inputs](../python-pbs/README.md), recorded offline Linux
image and Rust 1.88.0 available, use fresh evidence and build directories:

```sh
sh fixtures/python-runner/run-linux.sh target/python-runner-validation \
  target/python-runner-validation-build
```

The build cell verifies stock headers, compiles the five native images, runs the
independent public-API stock comparison, builds the shared runtime and preparer,
and builds `glue` with default Lua 5.4 plus `python-pbs`. It records ordinary
`doctor`, `inspect --json`, `verify` and `cat` results before removing producer
executables, headers, the preparer and all build intermediates. Those control
commands are separate from the execution traces; `verify` checks archive
payloads and does not verify external host files.

The runtime cell is offline, unprivileged and read-only, with no workspace mount,
an empty working directory, unavailable temporary paths and poisoned Python
environment variables. It captures all syscalls for these nine invocations:

| Mode | Expected result |
| --- | --- |
| `bundled-imports`, `host-imports` | Archive import/resource PASS, status 0 |
| `bundled-archived`, `bundled-host`, `host-archived`, `host-host` | Import/resource and native PASS, status 0 |
| `corrupt-native` | Stored dependency CRC rejection, status 1 |
| `missing-host-image` | Missing explicit dependency rejection, status 1 |
| `wrong-host-image` | Same-size altered host image rejection, status 1 |

Every invocation uses the relocated `glue run` command. No product fault flags
or alternate runtime selection are involved. Source-only success writes the
existing 100-byte line; native success adds its 69-byte line. Admission controls
produce no stdout and use the ordinary `glue:` diagnostic prefix.

The dedicated checker validates the exact product command, inherited evidence
streams and diagnostics, plus one bounded product target-readiness `uname`
query after the exact locator, manifest and ZIP metadata reads and before any
payload read. It then delegates acquisition, mapping, source import and finalization
records to independent instances of the unchanged earlier strict policies.
The archive is opened once and closes before host lookup. Native images remain
pinned through finalization; host trees must remain immutable for the complete
process lifetime. Failed source fallback, temporary-file materialization,
mutation, extra processes, early publication and unverified provider mappings
reject even when the attempted operation fails.

The emitted `native-metadata.json` retains the five image identities and exact
ELF load facts, seven native archive records, two source-only archive identities,
and each readiness query's exact byte count, cursor and read-range digest.
Compressed traces can be replayed without retaining the large
runtime archives:

```sh
python3 scripts/check-linux-python-runner-trace.py TRACE.txt.gz \
  --mode bundled-archived --stdout-file STDOUT.txt --stderr-file STDERR.txt \
  --archive-bytes ARCHIVE_BYTES --native-metadata-file native-metadata.json
```

The `corrupt-native` replay also requires `--corrupt-native-offset` from retained
metadata. Live captures use `--archive-file` and compare the complete archive
identity and manifest against that metadata. Historical probe commands and
their separate evidence remain regression controls.
