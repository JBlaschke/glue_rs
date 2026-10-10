# Explicit host Python startup experiment

The next A7/G1 slice starts the pinned stock CPython 3.13.16 / PBS `20261009`
library with its installed standard library on the observed GNU Linux arm64
cell. It extends `glue-python-bootstrap-probe`, with the same opt-in
`pbs-bootstrap` feature and C-owned initialization boundary. It does not yet
implement product host discovery or a general Python provider.

The prepared host archive contains only the shared startup app. Its manifest
explicitly selects `host` / `explicit_paths`, an installation library and stdlib,
the exact conventional-GIL/non-debug ABI, build identity and target. Host and
bundled manifest admission are separate and reject cross-provider selection.
The host path is canonical absolute ASCII with spaces allowed, at most 4,096
bytes, and uses the fixed layout `PREFIX/lib/libpython3.13.so.1.0` and
`PREFIX/lib/python3.13`. No runtime or frozen startup bundle is embedded in the
host archive, and acquisition never substitutes another provider.

Before loading Python, Rust rejects symlink/nonregular paths and ancestors,
opens and retains verified descriptors, streams the exact shared-library hash
and verifies all six startup source hashes against the pinned upstream input.
It requires the two startup `__pycache__` locations to be absent: disabling
bytecode writes alone would still permit pre-existing cached code. The library
loads from its verified read-only descriptor through GNU `ld.so`; no memfd or
payload materialization is involved in host acquisition. The runtime descriptor
and loader handle stay pinned through process exit.

This verifies the consumed startup subset, not every installed stdlib member.
The fixture keeps the installation on an immutable read-only mount. Retained
descriptors and inode checks do not freeze a mutable file's backing bytes or
bind Python's later source-path lookups against concurrent changes. General
mutable host installations need a separate identity/lifetime policy and evidence.

C bridge API revision 2 appends the public `PyWideStringList_Append` export to
the version-checked address table. All 21 function/data addresses must belong to
the selected image; the launcher has no link-time libpython dependency. C owns
the copied path buffers, `PyPreConfig`, `PyConfig`, Python references, diagnostics
and finalization. No Python object or configuration structure crosses Rust.

Host startup leaves the public frozen table untouched and rejects nonempty
custom entries. Stock private frozen modules remain available. Isolated public
configuration specifies installed prefix fields and exactly one stdlib search
path, disables environment/site/user-site/cache-write leakage, and fixes UTF-8
filesystem/stdio behavior. The executable is a virtual diagnostic identity.
See [CPython initialization](https://docs.python.org/3.13/c-api/init_config.html).

The same app checks version/build mode, UTF-8, isolation, `math`, `_ssl` and the
answer 42 in bundled and host cells. Its provider-specific assertions require
frozen encodings with empty search paths in the bundled cell, or the declared
installed encodings source with the one installed stdlib path in the host cell.
The ordinary-loader frozen baseline and installed-host result have different
encodings diagnostics; their application results agree.

Build-time fixture preparation verifies upstream inputs, preserves the exact
host library and installed stdlib sources, removes the producer executable,
headers, compiler intermediates and bytecode caches, and creates deliberately
invalid installations. Traced runs are unprivileged, relocated, read-only and
offline, without a workspace mount or Python executable, with poisoned Python
environment variables and unavailable temporary/home paths. Complete traces
must prove source verification before loading, only declared startup source
reads, private library mappings, exact diagnostics and exits, no payload
filesystem mutation, no extra process and no provider fallback.

Missing/altered libraries, missing/altered startup sources, symlinked stdlib and
existing startup bytecode caches must reject before Python image mapping.
An application error exercises the initialized C boundary separately. The
existing sealed-memfd bundled bootstrap remains a separate acceptance fixture.

G0/G1/G2 remain open. This observation is one installed-library/startup subset
on GNU Linux arm64. Product Python imports/resources, native extension loading,
other Python builds/versions, host discovery, other platforms and release
acceptance remain subsequent work.
