# Explicit installed Python startup fixture

This experimental GNU Linux arm64 fixture starts the exact pinned PBS CPython
3.13.16 library with an explicitly declared installed stdlib. The archive
contains only the shared app. Its manifest selects absolute library and stdlib
paths under an installation prefix containing spaces.

The launcher validates every archive byte, rejects symlinked host path
components and cached startup bytecode, hashes the unchanged library and six
startup sources, and holds the verified descriptors before loading the library
through its read-only `/proc/self/fd` alias. It configures isolated CPython with
exactly one search path: the declared stdlib. The app checks installed
`encodings`, built-in `math`/`_ssl`, isolation and the same result as the
[frozen startup fixture](../python-bootstrap/README.md). No custom frozen modules
are inserted in the installed-runtime cell.

The probe commands are:

```text
glue-python-bootstrap-probe prepare-host FULL_PBS_ARCHIVE FREEZE_BUNDLE PREFIX OUTPUT.glue
glue-python-bootstrap-probe run-host OUTPUT.glue
glue-python-bootstrap-probe run-host-negative OUTPUT.glue app-error
```

Preparation verifies the pinned upstream archive and matching producer bundle;
the selected host paths need not exist on the preparing computer. It creates a
new archive and never replaces an existing file. Execution requires the opt-in
`pbs-bootstrap` feature on GNU Linux arm64. Other targets fail before opening an
archive. The profile deliberately fixes one version, build and startup source
inventory; it is not general host-runtime discovery or version selection.

With both cached PBS inputs and the pinned Rust toolchain available, run from
the repository root:

```sh
sh fixtures/python-host/run-linux.sh target/python-host-validation \
  target/python-host-validation-build
```

Both output directories must be new. The harness uses the same offline pinned
Linux image as the frozen fixture. It provisions the producer and matching
headers at build time, runs the matching interpreter to produce the shared
bundle, builds/tests the C bridge and launcher, prepares the host archives, and
retains library/stdlib source identities. Before runtime, it removes the
producer executable, headers, Cargo intermediates, frozen archive and bundle,
and all valid-installation stdlib bytecode caches. The cache control deliberately
introduces a rejected cache directory. Build-time extraction supplies an ordinary
installed-runtime prerequisite; execution does not extract archive payloads.

A separate container has no workspace mount or installed Python executable.
Its inputs are read-only, its working directory is empty, temporary/home paths
are unavailable, Python environment variables are poisoned, and the traced
payload runs unprivileged. Eight complete syscall captures cover success,
wrong library, wrong stdlib source, missing encodings, symlinked stdlib, missing
library, cached startup bytecode and a controlled app error. Invalid installed
inputs must fail before any Python image mapping or initialization, with no
fallback to another runtime. The host trace checker requires complete archive
coverage, complete pinned input reads before the two private image mappings,
installed `encodings` source reads, exact diagnostics and exits, and admits only
the observed OS/import probes. Unknown calls, mutation attempts, bundled
fallback and extra processes fail even if the kernel rejected the operation.

The library's stock frozen internal modules remain stock CPython behavior.
General app imports, resources, installed extension loading, arbitrary host
Python distributions, other versions and other operating systems remain open.

The [clean observed capture](../../docs/evidence/pbs-linux-arm64-host-python-2026-10-10/README.md)
retains all eight host traces and a separate four-trace frozen-bootstrap regression,
with source/artifact identities, validation logs and replay instructions.
