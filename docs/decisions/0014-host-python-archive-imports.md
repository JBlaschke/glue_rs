# Archive application imports with an explicit host Python

This A7 slice uses the same archive source/resource adapter with the explicitly
installed stock CPython 3.13.16 / PBS `20261009` runtime on GNU Linux arm64.
It extends the controlled `glue-python-bootstrap-probe`; product provider
discovery and `glue run` Python execution remain subsequent work.

The host archive contains only the shared application, packages, assets and
trusted importer bootstrap: 18 resources. It declares `host` / `explicit_paths`
with the exact library, stdlib layout, ABI, target and build identity. The exact
manifest and every resource identity/compression must match this bounded
profile. No library, frozen startup bundle or stdlib source is embedded. All
archive resources are verified into immutable memory and the archive is closed
before any host runtime verification or loading.

The host owns its stdlib. In addition to the six startup sources, Rust verifies
63 reviewed import sources (1,372,061 bytes), giving 69 sources totaling
1,434,587 bytes. Their identities are independently tied to the complete pinned
PBS source inventory and checked against inspected upstream members during
preparation. This is the observed dependency closure of the shared importer and
conformance app, not a general installation or package compatibility policy.

Host verification rejects symlinked ancestors/files, nonregular or altered
sources and all 12 relevant `__pycache__` locations. Disabling bytecode writes
does not disable reads of existing caches: the stock CLI executed a planted
unchecked-hash cache in the development experiment. The supplemental source
profile therefore requires cache absence before hashing those sources. All
verified files are read to EOF, checked and rewound before loading Python.
Verified source/directory descriptors remain owned through finalization.

The library loads through its verified read-only descriptor alias. C leaves the
stock frozen table untouched, configures the installed prefixes and exactly one
stdlib search path, and disables environment/site/user-site/cache-write leakage.
The executable remains a virtual diagnostic identity. The installation is
immutable and read-only throughout execution; descriptor retention does not
freeze mutable backing bytes or bind Python's subsequent source-path lookups.
General mutable host installations require a separate policy and evidence.

Rust indexes only `app/python` modules and resources. Reserved names include
the selected image's 96 built-ins, its stock frozen names (including aliases),
bridge modules and all valid top-level roots of the pinned stdlib inventory.
App collisions reject before initialization. Built-in and stock frozen finders
retain precedence; the archive finder precedes the installed path finder.
Missing descendants of an archive-owned name reject before filesystem fallback,
and archive namespaces cannot merge with host portions. Deliberate installed
module/namespace/bytecode lures exercise those boundaries.

Both providers use the same Python loader/spec/resource implementation and
same conformance app. Host `importlib.resources` loads from its verified
installed source, then reads archive assets through immutable streams. The
virtual-origin syntax-error workaround, `as_file`/legacy `path` rejection and
finalization resource checks retain the scoped behavior described in
[the bundled decision](0013-python-archive-source-resources.md). General
traceback/linecache and compiler-warning consumers still need their own work.

C boundary API revision 3 and its 28 public exports are unchanged. A shared
invocation path supplies either the matching frozen records or explicit host
paths, while retaining Rust context, source owners and path buffers through the
synchronous C call and `Py_FinalizeEx`. No Python object crosses Rust, interpreter
patch or link-time libpython dependency is introduced.

The seven traced modes cover success, controlled app error, corrupt stored
archive source, wrong library, wrong/missing supplemental source and a nested
bytecode-cache directory. Corrupt archive source must reject before any host
lookup. Invalid installed prerequisites must reject before image mapping or
initialization. The complete strict policy requires archive closure, all
69 verified source reads and cache checks before loading, the exact runtime
source closure and directory probes, private library mappings, exact diagnostics
and exits, and no filesystem mutation, extra process or provider fallback.
The runtime cell is relocated, unprivileged, offline and read-only, without
workspace/producer/headers and with unavailable temporary paths and poisoned
Python environment variables. Earlier bundled/import and startup fixtures
remain separate regression captures.

G0/G1/G2 remain open. Both controlled providers now have a shared archive
source/resource experiment; product integration, native initialization through
supported CPython protocols, arbitrary packages, version selection and other
platforms remain subsequent work.
