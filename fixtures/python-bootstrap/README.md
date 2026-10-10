# Stock PBS Python bootstrap fixture

`glue-python-bootstrap-probe` is an experimental GNU Linux arm64 bootstrap,
separate from the product runner. It loads the unchanged CPython 3.13.16 / PBS
`20261009` library from a sealed memfd and installs six frozen startup modules
through public CPython APIs before isolated initialization. The app checks
`encodings`, `math`, `_ssl`, isolation, empty search paths and the expected result.

The upstream input pins are shared with [the PBS inspector](../python-pbs/README.md).
Both cached archives must be present. `freeze.py` verifies them and provisions
the matching stock compiler and installed headers at build time. Cross-host
provisioning does not execute target code; the exact compiler executes inside
the Linux arm64 container. Its marshal output includes source and producer
identities. The C bridge verifies the installed header tree before compilation.

From the repository root, with the pinned Rust toolchain on `PATH`, run:

```sh
sh fixtures/python-bootstrap/run-linux.sh target/python-bootstrap-validation \
  target/python-bootstrap-validation-build
```

Both output directories must be new. The build runs offline and uses the exact
cached image `62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`.

The probe CLI is:

```text
glue-python-bootstrap-probe prepare FULL_PBS_ARCHIVE FREEZE_BUNDLE OUTPUT.glue
glue-python-bootstrap-probe baseline OUTPUT.glue EXACT_STOCK_LIBRARY
glue-python-bootstrap-probe run OUTPUT.glue
glue-python-bootstrap-probe run-negative OUTPUT.glue missing-encodings
glue-python-bootstrap-probe run-negative OUTPUT.glue bad-bytecode
glue-python-bootstrap-probe run-negative OUTPUT.glue app-error
```

Preparation writes a new archive and never replaces an existing file. Normal
execution accepts exactly this fixed profile and verifies every resource before
loading code. Negative modes deliberately change already-verified in-memory
inputs to exercise initialization and app errors; they are fixture controls.
Build without `pbs-bootstrap`, or run on another target, to get status 2 before
opening an archive. Opt-in GNU Linux builds require an absolute
`GLUE_PYTHON_INCLUDE_DIR` with the exact pinned headers.

The Linux harness removes the producer installation and headers before the
archive run, relocates read-only inputs into paths containing spaces, poisons
Python environment variables, blocks temporary paths and captures complete
syscalls in a separate unprivileged container without a workspace mount. The
harness runs the trace checker on the host, since the pinned test image contains
no system Python. The ordinary comparison uses the same stock library and frozen
bundle; it is not the planned host-runtime provider.

The controlled OS profile admits normal loader libraries/cache, self process
maps, and PBS mimalloc's exact `overcommit_memory` read. Public CPython startup
makes one failed lookup of its virtual executable. `TZ=UTC0` uses the POSIX
timezone rule after one failed `/usr/share/zoneinfo/UTC0` lookup; no timezone
file bytes are read. The checker admits only those exact failed lookups, checks
complete archive byte coverage, both sealed private image segments, exact
stdout/stderr and the expected exit, and rejects unknown calls and mutation
attempts even when they fail. Captured diagnostics are also checked separately.

This fixture contains only startup stdlib code. General imports, resources,
extension loading and other platforms remain open. See
[the bootstrap decision](../../docs/decisions/0011-stock-pbs-frozen-bootstrap.md).
