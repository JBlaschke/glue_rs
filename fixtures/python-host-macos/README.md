# Explicit installed Python startup on macOS arm64

This experimental fixture starts the exact pinned stock PBS CPython 3.13.16 /
`20261009` macOS arm64 install-only library from an explicitly declared
installation. The archive contains only the shared startup app from the
[frozen startup fixture](../python-bootstrap/README.md). It is the macOS
counterpart of the [GNU Linux host startup fixture](../python-host/README.md)
and shares its six reviewed startup sources, whose bytes are identical in both
artifacts. See [decision 0031](../../docs/decisions/0031-macos-python-host-startup.md).

The launcher validates every archive byte, rejects symlinked host path
components and startup bytecode caches, hashes the unchanged library and six
startup sources through retained descriptors, and then lets dyld load the
library by its verified path. The mapped image's `LC_UUID` must equal the
verified bytes' `LC_UUID`, the dyld image table may gain only that image and
OS libraries, and all 29 API exports must resolve inside it. Isolated CPython
sees exactly one search path, the declared stdlib, and the app checks
installed `encodings`, built-in `math`/`_ssl`, isolation and the same result
as on Linux.

```text
glue-python-bootstrap-probe prepare-host-macos INSTALL_ONLY_ARCHIVE PREFIX OUTPUT.glue
glue-python-bootstrap-probe run-host-macos OUTPUT.glue
glue-python-bootstrap-probe run-host-macos-negative OUTPUT.glue app-error
```

Preparation verifies the pinned artifact in [pins.json](pins.json) and selects
its library and startup sources without extraction; the declared prefix need
not exist on the preparing computer. Execution requires the `pbs-bootstrap`
feature built on macOS arm64 with `GLUE_PYTHON_INCLUDE_DIR` naming the
artifact's installed header tree, which the build script checks against
[header-pins.json](header-pins.json). Other targets, and Mac builds without
that header tree, fail with the unsupported status before opening an archive.

Download the exact artifact named in `pins.json` to `target/pbs-macos/`, then
run from the repository root with a new output directory:

```sh
sh fixtures/python-host-macos/run-macos.sh target/python-host-macos-validation
```

The harness verifies the artifact, extracts it into a fresh read-only prefix
containing a space, removes the three shipped encodings caches, builds, tests
and lints the probe against the verified headers, derives six rejected control
installations, prepares all archives, and runs every case with poisoned Python
environment variables and unavailable home and temporary paths. It snapshots
the installation before and after the runs and requires it unchanged.
`check-results.py` compares every status and diagnostic with the expected
values. No syscall tracer is available without root on macOS; the evidence
records that limitation rather than claiming a trace.

On the same cell the product runner serves the prepared archive. Build `glue`
with `--features python-pbs` and the same `GLUE_PYTHON_INCLUDE_DIR`; then
`glue doctor OUTPUT.glue` reports readiness from the declared target and the
observed macOS version and page size, and `glue run OUTPUT.glue` prints the
same PASS line. The six rejected installations and the loader override reject
through `glue run` with the `glue:` prefix. See
[decision 0032](../../docs/decisions/0032-macos-python-product-route.md).

The checked-in product harness repeats that capture from the repository root
with the same artifact and a new output directory:

```sh
sh fixtures/python-host-macos/run-product-macos.sh target/python-host-macos-product-validation
```

It runs the default-feature workspace checks first, extracts the artifact into
a fresh read-only prefix, builds `glue` with `python-pbs` and the probe with
`pbs-bootstrap` against the verified headers, copies both aside, runs the
feature-enabled tests and lints, builds a second launcher without the header
tree in `target/no-boundary`, derives the six control installations and
prepares the seven archives. One GNU Linux arm64 declaration is staged
portably from the [metadata fixture](../python-metadata/README.md) input
against a fixed absent prefix and packaged by `glue build`. Every `doctor`,
`inspect`, `inspect --json`, `verify` and `run` receipt runs from an empty
working directory in the fixture's poisoned environment, with
`DYLD_LIBRARY_PATH` set only in the loader-override case.
`check-product-results.py` compares each status, stdout and stderr with the
expected exact values, recomputing the printed manifest digests from the JSON
receipts, and requires the installation snapshot unchanged. See
[decision 0033](../../docs/decisions/0033-macos-python-product-harness.md).

Bundled macOS Python, native extensions, installation discovery, the complete
stdlib and the distribution signing policy remain separate work.
