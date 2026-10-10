# Python archive source imports and resources

This A7 slice extends the controlled stock PBS experiment with source imports
and resources after isolated frozen startup. It is a bundled GNU Linux arm64
fixture for conventional-GIL, non-debug CPython 3.13.16 / PBS `20261009`, separate
from product runtime acquisition. The existing frozen and installed-host cells
remain regression fixtures; archive imports with an installed host runtime need
their own subsequent evidence.

The new archive includes the unchanged stock shared library, the six-module
matching-producer startup bundle, a trusted importer bootstrap, the app and its
package assets, and a source-only stdlib projection. All 2,174 regular `.py`
members below the pinned installation's stdlib are preserved byte-for-byte:
39,158,056 source bytes, including tests, idlelib and site-packages sources. This
is an explicit source-only profile, not a complete installation or a promise
that all those packages work. Site-packages is not added to search paths. Native
extensions, stdlib data files, wheels, bytecode and path-required APIs need
separate supported profiles and tests.

The complete source inventory is pinned in
[`stdlib-pins.json`](../../fixtures/python-imports/stdlib-pins.json), derived from
the independently retained full-PBS inventory. Preparation verifies the complete
upstream input and exact projection. Admission checks provider/build/target,
every source/app/helper identity and compression, and bounded resource counts
and sizes. Rust verifies and decodes all source/assets before loading Python,
then closes the archive. Requests use only immutable verified memory, with
4 MiB per reply and a 48 MiB source/resource collection bound. This eager
fixture establishes correctness rather than a final lazy-cache/memory design.

Rust owns module resolution and resource metadata. App modules live below
`app/python`, stdlib sources below `stdlib`; overlapping top-level names are
rejected. A source package has `__init__.py`, a module has `.py`, and a directory
otherwise supplies a single-archive namespace portion. Source modules precede
implicit namespaces; simultaneous module/regular-package definitions reject.
Canonical resource paths follow the existing schema-zero ASCII contract.
Missing descendants of a declared top-level archive name cannot fall through
to a filesystem finder. Built-in and stock frozen finders keep precedence.

The Python shim implements CPython's loader/spec protocols, compiles source
bytes with encoding-cookie support, and preserves import caching, relative and
circular imports, reload and failure cleanup. Imported source modules have
`glue://` origins, `__file__` and code filenames, with no cache pathname. Namespace
packages use a resource-aware zero-code loader, one virtual search location and
no host-location merging. The adapter uses those identities without OS paths.
See [the import protocol](https://docs.python.org/3.13/library/importlib.html).

Stock CPython attempts to reopen a compile filename while constructing some
syntax errors, including angle-bracket pseudo filenames. The observed GNU Linux
UTF-8 filesystem encoder rejects an unpaired high-surrogate sentinel before any
OS lookup. The shim compiles against that sentinel, then recursively restores
the virtual origin with public `code.replace`; syntax errors restore both the
filename attribute and argument detail while retaining source text and offsets.
This mechanism is specific to this verified provider/encoding profile. Other
providers need their own diagnostic-path evidence before using it.
General traceback/linecache consumers and compiler warnings are outside this
fixture's verified behavior; virtualizing their source lookups needs further work.

Actual stock `importlib.resources` loads from the archive. Its resource reader
and Traversable objects offer immutable binary/text streams, read/readinto,
seek/tell, directory enumeration and UTF-8 text by default. Writes, truncation,
file descriptors, path coercion and traversal are rejected. The pinned 3.13
implementation's `as_file` singledispatch registers the archive Traversable to
raise an actionable error before temporary-file attempts, for both files and
directories; the legacy `path` helper shares this behavior. This registration
mechanism is version-specific behavior, not a documented cross-version hook.
Use `read_bytes`, `read_text` or `open` instead. See
[resources](https://docs.python.org/3.13/library/importlib.resources.html) and
[Traversable](https://docs.python.org/3.13/library/importlib.resources.abc.html).

C boundary revision 3 appends seven public exports to the selected-image table
(28 total). It creates `_glue_archive.request(str) -> bytes` using supported C
APIs. Requests and replies are length-delimited and bounded. Rust catches
callback panics and forgets exceptional panic payloads so a panicking destructor
cannot unwind into C; C copies and releases every reply before subsequent Python
API calls or error propagation. C owns Python objects/configuration/diagnostics
and finalization; no Python object crosses Rust. The borrowed immutable context
remains live through finalization, on the one calling thread. The trusted
bootstrap runs in its own module globals after initialization and before the app.
An application `atexit` callback reads binary/text resources to exercise that
context lifetime during actual interpreter finalization.
No interpreter patch or direct libpython link is introduced.

The fixture exercises nested, relative, circular and namespace imports, reload,
source encoding, failed-import cleanup, virtual metadata, binary/Unicode assets,
independent streams and resource rejection paths. Ordinary loading of the same
library/archive provides a comparison. Relocated unprivileged execution has no
producer/stdlib/headers/workspace, read-only inputs, no network, poisoned Python
environment variables and unavailable temporary paths. Complete traces require
archive verification/closure before the sealed image, exact stdout/errors/exits,
no payload filesystem mutation, source fallback or extra process. Corrupt stored
source must reject with an exact CRC diagnostic before any memfd attempt.

G0/G1/G2 remain open. This source/resource observation does not establish product
Python execution, host-provider archive imports, native extension semantics,
arbitrary package compatibility, other Python versions, other platforms or release
acceptance. The next A7 work is shared-adapter/product integration and native
initialization through supported CPython protocols, with both providers tested.
