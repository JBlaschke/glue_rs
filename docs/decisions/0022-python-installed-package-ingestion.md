# Source-only Python installed-package ingestion (A7/A10)

Status: implementation contract, 13 October 2026.

Add an opt-in Rust build-time adapter in `glue-pack`, exposed by
`glue build-python`. The caller selects a previously admitted metadata-profile
manifest and its provider input root, an application tree, and either an
explicit site-packages directory or a conventional Python 3.13 venv. Preserve
the template's exact runtime, target, provider and non-application resources.
Replace its application identity, entry and application inventory. Reuse the
runtime's portable metadata admission/content policy through a narrow build
facade. No runtime profile, helper identity or native loader changes are needed.

The `python-pack` runner feature supports portable/cross-target packaging
without a Python compiler or runtime initialization; `python-pbs` includes it.
The adapter neither runs the input interpreter nor imports application packages,
activates a venv, invokes pip, downloads inputs or resolves dependencies.

## Inputs and transformations

The application input uses the existing `app/` tree layout. An installed package
tree is treated as a complete bounded inventory, with top-level `.dist-info`
directories and one RECORD owner for each retained file. No implicit pruning of
pip, setuptools, dependencies or package assets occurs. Seeded environments may
exceed the existing application caps; diagnose that and require a deliberately
prepared source-only package tree. Empty directories are not resources.

The venv convenience mode reads a bounded `pyvenv.cfg`, requires conventional
Python 3.13 and `include-system-site-packages=false`, and selects only
`lib/python3.13/site-packages`. It does not resolve `home`/`executable` or inspect
interpreter/activation scripts. Those legitimately include symlinks. The
configuration is provenance/layout, not proof of the selected target ABI or
package compatibility. Free-threaded, ambiguous and Windows layouts remain
outside this initial convenience mode; an explicit package directory can still
be supplied independently of its originating host.

Parse bounded UTF-8 METADATA/RECORD without importing installed code. Reuse exact
Name/Version/directory agreement and strict three-column CSV policy. Verify each
retained original hash/size when supplied. Retain package source, data and
metadata, including nested license/data files. Installed WHEEL metadata must
declare purelib and compatible `py3`/`py313` none-any tags; those declarations
do not prove general package compatibility. Reject native filenames, path
hooks (`.pth`), legacy editable/egg metadata and `direct_url.json` with an editable
declaration. Retained roots/components/files must be regular and symlink-free.
The caller must keep build input trees stable during reads, as for ordinary build.

Omit bytecode/cache inputs and report them. Installed RECORDs may name generated
console/gui wrappers outside site-packages. Only a narrow exact
`../../../bin/<name>` path whose name is declared in that distribution's console
or GUI entry-point group may be omitted, without reading or resolving that
external path. Preserve entry-point metadata for archive plugin discovery.
Reject absolute paths, arbitrary traversal and unknown external wrappers.
Detect duplicate paths and shared ownership before filtering.

Rewrite RECORD deterministically for the retained inventory: canonical relative
paths, SHA-256 and actual size, with an empty hash/size self-entry. Report original
RECORD identity, retained input identities and every omission. Source/data and
other metadata bytes remain unchanged. Existing limits still apply: 64
distributions, 1,024 RECORD rows each, 1,024 application files, 8 MiB application
bytes, 4 MiB per file and 64 KiB entry. Bound directory traversal as well as copied
bytes. Reject collisions with explicit app files, stdlib names and ambiguous
module/package/namespace layouts through the existing runtime policy.

## Publication and evidence

Read and verify all inputs, construct/admit the final manifest and metadata,
and verify the generated archive before creating the output with `create_new`.
Failures before publication leave an absent output absent and an existing
output unchanged. A failed output write can leave a partial file, as documented
for ordinary builds. Structured stdout (`--json`) publishes deterministic
transformation and artifact reports without an additional output transaction.

Use a real offline installation of a checked-in tiny pure-Python wheel, including
generated caches and a console wrapper. Product builds must run the metadata app
through all three providers using the unchanged runtime trace policies. Hostile
build controls cover integrity, traversal, unsupported layouts, collisions,
symlinks, bounds and existing-output protection. Cross-target Mac packaging must
not invoke the input interpreter. Retain genuine GNU Linux execution evidence;
this is not acceptance of arbitrary packages, general wheel installation,
dependency solving, native packages or additional runtime/platform cells.

Primary references: [installed-project RECORD](https://packaging.python.org/en/latest/specifications/recording-installed-packages/),
[entry points](https://packaging.python.org/en/latest/specifications/entry-points/),
[wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/),
[direct URL metadata](https://packaging.python.org/en/latest/specifications/direct-url-data-structure/),
[Python venv](https://docs.python.org/3.13/library/venv.html).
