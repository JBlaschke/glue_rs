# Source-only Python distribution metadata (A7)

Status: experimental contract, 12 October 2026.

Add three explicitly selected metadata-aware source application identities for
the existing pinned bundled, full-host and install-only host PBS providers.
The runtime remains stock CPython 3.13.16 / PBS `20261009`, conventional GIL,
GNU Linux arm64. Existing source/fixture identities, importer bytes, source
inventories, startup caches, C boundary and native loader remain unchanged.

The new build IDs end in `bundled-metadata-apps-v1`, `host-metadata-apps-v1`,
and `host-install-metadata-apps-v1`, respectively. The bundled artifact variant
is `pgo+lto-full/bundled-metadata-apps-v1`. Each new archive also declares the
exact trusted `python/archive-metadata.py` helper, stored with deflate. Portable
admission verifies that helper and reuses the corresponding source application
policy after restoring its legacy declarations in a temporary view. Execution
verifies original archive bytes and metadata before acquiring either provider.
No provider retry or filesystem discovery is added.

## Admitted metadata

Only top-level `.dist-info` directories below `app/python` participate in
distribution discovery, with at most 64 distributions. Each directory requires
`METADATA` and `RECORD`. Names and versions are bounded ASCII identifiers;
Name normalizes case and runs of dots, underscores and hyphens. The directory
name and METADATA identity must agree, and normalized distribution names must
be unique. Versions use the exact canonical directory spelling; this initial
profile does not implement general version normalization or dependency solving.
METADATA is UTF-8 and at most 64 KiB. Identity headers occur exactly once and
cannot use continuation lines. Other metadata fields retain their contents.

RECORD is UTF-8 CSV, at most 256 KiB and 1,024 rows, with exactly three fields
per row. Quoted comma-containing paths are supported. File names must be
canonical archive paths relative to `app/python`, refer to declared files and
remain within that root. Duplicate entries, traversal, other distributions'
metadata and shared file ownership reject. Every metadata file must be listed,
including RECORD itself with empty hash/size. Other rows may omit hashes/sizes;
when present, sizes must match and hashes must be SHA-256 in unpadded URL-safe
base64 and match verified bytes. Archive hashes independently verify every
resource. Optional `top_level.txt` and `entry_points.txt` are bounded UTF-8.

This is a closed source-only metadata profile. Native/bytecode payloads and
metadata `.py` paths that violate the existing module hierarchy still reject.
Wheel installation, venv ingestion, editable installs, `.pth` execution,
`.egg-info`, external script locations and general native packages remain
separate A7/A10 work. Supporting distribution metadata does not prove arbitrary
package compatibility or a complete dependency closure.

## Public Python behavior

The trusted helper augments the existing archive finder using the public
`importlib.metadata` distribution extension mechanism. It imports the metadata
stdlib lazily on the first query. Application distribution names remain
distinct from import module names. Supported operations include `version`,
`metadata`, `requires`, `entry_points`/`EntryPoint.load`, `files` and
`packages_distributions`. Plugin loading continues through the archive importer.
See [Python's metadata extension mechanism](https://docs.python.org/3.13/library/importlib.metadata.html#extending-the-search-algorithm)
and [installed-project metadata](https://packaging.python.org/en/latest/specifications/recording-installed-packages/).

Default discovery exposes archive distributions even with an empty `sys.path`.
An explicitly supplied Context path filters by the virtual `app/python` root;
an empty list or unrelated physical path excludes these distributions. The
helper never examines host site-packages. Existing source-host isolation keeps
the ordinary filesystem finder out of `sys.meta_path` after startup.

`Distribution.read_text` returns None for an absent optional metadata file.
`locate_file` and `PackagePath.locate` return immutable virtual objects with
stream/byte/text reads and `exists`, sufficient for the stock metadata files
API. They cannot become filesystem paths. Existing `importlib.resources.as_file`
rejection applies to these objects too, before any temporary-file operation.
No extraction or filesystem API virtualization is introduced.

## Evidence boundary

Require the same metadata application through all three providers, exercising
version/requirements, plugin loading, RECORD file resources, import-name
mapping, name normalization, Context filtering and missing distribution/host
lure behavior. Invalid RECORD paths and corrupted stored metadata must reject
before any host runtime lookup or bundled runtime memfd. Portable policy tests
exercise bounded parsing and integrity failures. Existing source profile traces
remain regression evidence. Complete Linux traces must distinguish approved
host prerequisites from undeclared metadata reads and reject payload mutations.
Other platforms, runtime versions, generic venv/wheel admission and G3/G4/G5
acceptance remain open.
