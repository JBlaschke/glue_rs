# Python archive source and resource fixture

This controlled GNU Linux arm64 fixture starts unchanged pinned stock CPython
3.13.16 / PBS `20261009`, then imports source modules, packages and a one-portion
namespace package from its archive. Actual `importlib.resources` reads binary
and UTF-8 assets through immutable seekable streams. Virtual `glue://` origins
are diagnostic identities; `as_file`, legacy `path` and OS path coercion cannot
materialize these resources.

The source-only archive preserves all 2,174 regular `.py` stdlib members from
the pinned full input (39,158,056 bytes), plus the fixture app/packages/assets.
The projection includes development/site-packages sources without adding
site-packages to import paths. This is not full-stdlib or arbitrary-package
acceptance. Six matching-producer frozen startup modules still establish
encodings before the source importer is installed. Rust verifies every source
and asset before loading Python, then serves bounded immutable-memory requests
through the C-owned Python boundary.

The probe supports:

```text
glue-python-bootstrap-probe prepare-imports FULL BUNDLE OUTPUT.glue
glue-python-bootstrap-probe baseline-imports OUTPUT.glue LIBRARY
glue-python-bootstrap-probe run-imports OUTPUT.glue
glue-python-bootstrap-probe run-imports-negative OUTPUT.glue app-error
glue-python-bootstrap-probe corrupt-imports INPUT.glue CORRUPT.glue
```

`prepare-imports` verifies pinned input identities and creates a new output.
`corrupt-imports` creates a separate archive whose stored package source fails
CRC verification. Other targets/builds reject execution before opening an archive.

With the cached PBS inputs and pinned Linux image/toolchain available, run from
the repository root using new output directories:

```sh
sh fixtures/python-imports/run-linux.sh target/python-imports-validation \
  target/python-imports-validation-build
```

The harness freezes startup modules at build time, runs release tests/Clippy,
prepares archives and captures the ordinary-loader comparison. It then removes
the producer, stdlib, library files, headers and Cargo intermediates. A separate
read-only/offline container runs the relocated launcher/archive unprivileged,
without workspace access and with unavailable temporary/home paths. Three full
traces cover success, application error and corrupt source. Mutation attempts,
filesystem source fallback and extra processes fail the strict trace policy.

The successful output is 100 bytes:

```text
PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42
```

The app covers import caching/reload, circular/relative imports, namespace
resources, Latin-1 source cookies, failed module cleanup, ignored bytecode,
virtual metadata, binary/Unicode assets, independent stream positions and
read-only/traversal/materialization controls. The `.pyc` fixture is deliberately
non-executable text used to prove it is ignored. `test_importer.py` provides
16 additional protocol tests with a fake resource callback; run it with Python 3.13
for the pinned API behavior. Those portable tests do not prove runtime loading.
Syntax-error diagnostics retain virtual origins without OS source lookups using
a sentinel rejected by this provider's UTF-8 filesystem encoder; this technique
needs separate verification on other providers. An `atexit` callback reads both
binary and text resources during finalization.

Product Python execution, host-provider archive imports, native extensions,
other runtimes/versions/platforms and general package support remain open. See
[the decision](../../docs/decisions/0013-python-archive-source-resources.md).
