# Pinned install-only host Python source applications

This A7 increment starts from merged `442d9eb` on
`codex/a7-install-only-host-source-apps`. It adds an explicit host source-app
profile for the independently pinned unstripped CPython 3.13.16 / PBS
`20261009` install-only distribution on the reviewed GNU Linux arm64 target.

The separate build identity is
`pbs-20261009-cpython-3.13.16-pgo-lto-host-install-source-apps-v1`. Existing
bundled/full-source host identities retain their admission and cache policies.
The selected host paths keep the canonical absolute ASCII prefix layout;
runtime ABI, target, conventional GIL and non-debug declarations stay pinned.

## Installed sources and startup caches

The install-only source projection contains 1,037 files totaling 15,894,268
bytes. Every source identity agrees with the full distribution. The omitted
1,137 files are 1,072 below `test/` and 65 below `idlelib/`. All 122 encoding
sources and 404 site-packages sources remain. This is an explicit distribution
choice, not reachability pruning. The library keeps its exact existing pin.

The stock archive also contains three timestamp-based encoding caches totaling
21,157 bytes. This profile requires their exact size/hash identities and a
closed `encodings/__pycache__` directory containing only those three files.
Sources, caches and ancestors reject symlinks/nonregular candidates. Extra
startup shadows and every other derived source-cache directory reject before
loading. Cache, startup and directory owners remain live through finalization;
individual snapshot source descriptors close after verified bytes are owned.
Portable path validation also caps total retained descriptors, rather than
inferring that bound solely from the smaller source-directory count.

Stock tar source/cache mtimes are normalized to 2024-01-01, whereas cache
headers name a different timestamp. The conformance harness preserves the
stock mtimes and must observe CPython's actual stale-cache handling. Pinned
cache bytes remain trusted startup inputs; the evidence must distinguish
cache probes, source reads and later snapshot imports.

All sources are snapshotted before initialization. The original trusted prelude
then disables default filesystem import fallback and installs the unchanged
source importer. Later modules/resources consume owned bytes with virtual
origins; initialized host/frozen metadata remains stock. The full runtime-name
collision set stays reserved even where install-only omits sources. Missing
snapshot modules do not select another provider or become host path imports.

## Packaging and prerequisites

App admission, byte-entry semantics and archive budgets match the existing
host source-app contract. The archive contains only the pinned importer and
`app/` resources; builder admission happens before input/resource/output I/O.
Doctor checks declarations/build/target readiness without acquiring a host.

A bounded build-time helper verifies the exact install-only artifact before
materializing its declared installation. It preserves source/cache bytes and
stock mtimes, records any fixture transformations, and stages applications
without a full-distribution runtime archive or a runtime download. The host
profile verifies its selected source/library/cache prerequisites; it does not
claim that every other file in an installation has been verified or exposed
as an import. Native files and arbitrary site-packages remain outside this
source resolver's compatibility contract.

The installation/startup paths must remain immutable and read-only through
execution/finalization, and mapped library backing must remain immutable for
process life. Hashes and descriptors do not freeze mutable backing files.
Trusted code can alter import machinery or perform host I/O.

This does not add runtime discovery, version selection, arbitrary uv/system
installation compatibility, wheels, extension discovery, workers or another
platform. The C boundary and selected GNU mapping mechanism remain unchanged.
G0/G1/G2 remain open. See
[the full-source host contract](0018-host-python-source-apps.md).

The [clean install-only host evidence](../evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains 16 new and 61 prior-route traces from `7a8e32c`, compressed replays,
exact CLI controls, the complete provider audit and 894 rejected hostile edits.
