# P02 compact stock-Python provider

`python::compact::build(&CompactBuildOptions, launcher, output)` discovers an
existing environment, chooses its compatible stock interpreter, assembles the
runtime/native closure and archived stdlib, and atomically publishes through the
shared distribution builder. The generic launcher does not embed CPython or need
CPython headers. Inputs are never installed, downloaded or recompiled.

The bundled layout follows the selected runtime's native prefix, with its stdlib
as `runtime/lib/pythonXY.zip` and one loose bounded `support/python-bootstrap.py`.
Native stdlib/dependencies use the existing OS loader and C03/C04 collectors.
Frameworks or other absolute native load paths require the explicit normalization
option; all native edits and re-signing identities are reported by the collector.
Framework discovery chooses the installed real interpreter inside
`Resources/Python.app/Contents/MacOS/Python`; the usual `bin/pythonX.Y` stub can
exec an original-prefix app and is unsuitable as the deployed executable.
With explicit normalization, the real executable deploys as `runtime/bin/Python`.
This standalone layout permits strict final signature validation without an
incomplete `.app` bundle resource envelope. The existing core image remains at
the runtime root, with the executable's dependency rewritten by C04.
The bootstrap handles frozen-encodings package paths observed in newer stock
builds, checks the exact interpreter version and rejects prefix fallback before
application execution. Runtime flags are always `-I -S -B`.

Local PBS full/install-only/stripped archives are inspected with the bounded
existing tar parser, then staged exclusively at build time. Runtime archives
have a 1 GiB compressed/staged-runtime bound and a 128 MiB retained-memory bound per
independently verified selection pass. Larger ordinary full/install-only trees
are staged in bounded batches (headers,
static development archives and full-build debug bundles are excluded). Symlink
aliases resolve to already-validated regular bytes. Full archives select
`python/install`, install-only inputs select `python`. The source archive identity
and selected source/native identities enter the offline lock. No pin catalog
controls admission and no staging operation happens at application startup.

Explicit `RuntimeProvider::Host` remains a separate mode with the declared host
executable/prerequisites. It does not satisfy bundled-provider acceptance. Source
and package behavior uses P03's verified importer. P04 adds application-native
mapping through the same build interface. Tcl/Tk external script data requires an
additional resource adapter; this is declared in runtime requirements rather than
silently using the original prefix. General multiprocessing spawn behavior is
outside the executed corpus.

The focused native test copies a supplied runtime to a controlled input, builds,
moves output to a path with spaces and `é`, removes its runtime/project/environment
inputs, disables payload write permissions and runs from `/` with empty PATH and
unusable HOME/temp. It checks encodings (including cp437), math/ssl, a deployed
native stdlib module, exact version and argv. It passed on macOS arm64 PBS 3.13.16,
3.14.5, 3.15.0b1 and Homebrew framework CPython 3.14.8 with explicit normalization.
The framework test independently prepares its controlled input's real app
executable to avoid its original-prefix stub before product discovery. Only
ad-hoc signing was tested. A local PBS 3.13.16 install-only archive override also
passed. Preserve-mode Linux PBS 3.13.16 diagnosed Tcl/Tk's non-relative ELF search
path as requiring explicit normalization; this is not hidden by source-only tests.
The Linux arm64 corpus then passed in the cached Rust 1.88 container with network
disabled, explicit normalization, independently supplied patchelf and the declared
`/usr/lib/aarch64-linux-gnu` search root. No runtime installation was performed.
P05 records additional providers/versions and V02/R02 record real target tracing;
this test alone does not prove no runtime writes or offline isolation.

`build_with_options` additionally accepts build context recorded in the lock.
The reserved `glue.expected-runtime` JSON descriptor is compared before atomic
publication, then removed from recorded options. A mismatch in implementation,
version, provider, target, ABI or runtime input identities raises `PayloadIntegrity`.
Runtime identities include original bytes of the interpreter/native-stdlib seed
closure and every transitive bundled dependency, including external search roots.
Application-only native images are excluded from the runtime descriptor so an
application rebuild can change packages without replacing the selected runtime.
Public build APIs return stable `Diagnostic` codes; lower-level compatibility
wrappers retain their prior string-error interface. Runtime version strings keep
prerelease/build suffixes separately from the numeric ABI tuple.

```sh
GLUE_TEST_PYTHON=/supplied/bin/python3.13 cargo test -p glue-pack \
  --features python --test python_compact -- --include-ignored
# Also exercise an independently supplied local PBS archive:
GLUE_TEST_PYTHON=/supplied/bin/python3.13 \
GLUE_TEST_PYTHON_ARCHIVE=/supplied/python-install_only.tar.gz \
cargo test -p glue-pack --features python --test python_compact -- --include-ignored
```
