# Pinned explicit-host Python source applications

This A7 increment starts from merged `cb3cae4` on
`codex/a7-host-source-apps`. It pairs the bounded source-application contract
with an explicit host CPython 3.13.16 / PBS `20261009` provider on the reviewed
GNU Linux arm64 target.

## Admission and source ownership

The build identity is
`pbs-20261009-cpython-3.13.16-pgo-lto-host-source-apps-v1`. The manifest selects
`host` with explicit canonical absolute ASCII paths to
`PREFIX/lib/libpython3.13.so.1.0` and `PREFIX/lib/python3.13`. Runtime ABI,
target, conventional GIL and non-debug declarations retain the existing pins.
Doctor checks portable declarations and build/target readiness; it does not
inspect or acquire the installed provider.

The archive contains the unchanged pinned source importer and application-owned
`app/` resources. Entry, component and app identities use the same bounded
policy as the bundled source profile. Modules resolve below `app/python/`;
assets and the declared entry may live elsewhere below `app/`. Runtime/stdlib
names cannot be shadowed. Native modules, host imports and bytecode payloads
remain outside this profile.

Application budgets stay 1,024 files, 8 MiB combined, 4 MiB per file and 64 KiB
for the entry. The host archive has a separate 16 MiB archive/total bound,
1 MiB manifest, 2,048 entries, 4 MiB member and 256 KiB central directory bound.
`glue build` applies this admitted policy to the same parsed manifest before
input-root/resource/output access. It does not include or acquire host files.
Other profile limits remain unchanged.

Execution verifies every archive resource and closes its owner before host
access. It then verifies the exact installed library and all 2,174 independently
pinned sources from the full PBS source projection, totaling 39,158,056 bytes.
Expanded source and cache paths validate before acquisition. The projected
hierarchy plus prefix ancestors may require at most 256 distinct retained
directory owners; this bounds snapshot/startup owners to at most 763 descriptors
before existing process and temporary loader descriptors. Cache locations
derived from the source-directory hierarchy must be absent. Symlink/nonregular
sources, missing/changed contents and startup shadow candidates reject before
runtime loading. Source files are read with bounded memory and descriptor use;
owned verified bytes form the same immutable source index used by the bundled
provider.

This full projection is explicit: the install-only distribution contains only
1,037 of these sources. Preparing the projected host tree from the verified
full input supplies the required inventory. This increment does not silently
weaken the inventory to fit another installation.

## Startup and imports

The unchanged C boundary initializes the host library with its installed
stdlib path. Startup codecs/encodings therefore still read approved installed
sources. Their caches and possible native/bytecode shadows need checks before
initialization; merely disabling bytecode writes would not prevent cached code
from being read.

A trusted profile-specific prelude runs before the unchanged shared importer.
It removes the default filesystem `PathFinder`, clears `sys.path`, path hooks
and importer cache, then removes its temporary aliases. Builtin/frozen importers
remain active. The shared source importer resolves later app and stdlib modules
from owned bytes. Extra host source, standalone bytecode or native-module lures
cannot become ordinary import fallbacks. This describes default supported
imports; trusted Python code can change import machinery or perform host I/O.

Later source modules use virtual `glue://` origins and immutable resource
streams. Already initialized host startup/frozen modules retain their stock
metadata. Pinned source bytes include site-packages files and configuration
sources that the existing module resolver does not expose as top-level modules;
the inventory is not a claim of full stdlib/package compatibility. Path-required
consumers and materialization remain separate work.

The entry uses the same byte-based script launcher and `__main__` metadata as
the bundled profile. Application arguments, `-m`, full traceback rendering and
standalone Python exit-code behavior remain open. Uncaught exceptions including
`SystemExit(None)` and `SystemExit(0)` retain a bounded message and status 1.
The C owner controls one synchronous initialization/execution/finalization
lifecycle. The snapshot and archive callbacks remain live through finalization;
the selected library remains pinned for process life. C boundary API4 and its
29 exports/240-byte table remain unchanged.

## Host prerequisite and scope

The installed library and startup path hierarchy must stay immutable and
read-only throughout execution and finalization; the mapped library backing
must remain immutable for process life. No-follow checks, hashing and open descriptors
do not freeze mutable backing files or bind all later pathname lookups. The
source snapshot reduces subsequent filesystem dependence; it does not remove
the host startup prerequisite.

Existing exact host fixtures retain their six/69-source validators and ordinary
installed-stdlib behavior. This new profile broadens application and verified
source ownership without runtime discovery, version selection, generic wheels,
extension-file loading, workers or another platform. G0/G1/G2 remain open.

See [the bundled source application decision](0017-bundled-python-source-apps.md)
and [the existing host-import decision](0014-host-python-archive-imports.md).

The [clean host source-app evidence](../evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/README.md)
retains all 13 new and 48 prior-route traces from `dd6274f`, with compressed
replays, exact CLI controls and the independent 567-edit rejection audit.
