# Product Python runtime templates (A7/A10)

Status: implementation contract, 13 October 2026.

Add `glue python-template` under the existing `python-pack` feature. It prepares
`manifest.json`, `root/` and `provenance.json` for direct use by `glue build-python`,
without running Python or invoking the historical fixture preparers. The three
provider choices remain the exact stock CPython 3.13.16 / PBS `20261009` metadata
profiles on GNU Linux arm64. No runtime/helper/loader identity changes are needed.

```text
glue python-template --provider bundled --pbs-full FULL.tar.zst \
  --frozen-bootstrap BUNDLE.json --output DIR [--json]
glue python-template --provider host-full --host-prefix PREFIX --output DIR [--json]
glue python-template --provider host-install --host-prefix PREFIX --output DIR [--json]
```

The bundled input is the already pinned full PBS artifact. Read and validate it
through the existing bounded selective inspector, retaining only libpython and
the exact 2,174-source projection. Compare the complete artifact's regular `.py`
projection with the expected set; verify each selected identity. Preserve the
library and source bytes, and use the compiled-in importer/metadata helper bytes.
The explicit frozen startup input must match the existing complete 139,523-byte
identity `6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`,
then pass bundle parsing and source/producer validation against the inspected
artifact. Self-declared marshal hashes alone are insufficient. This startup
artifact was already produced by the verified stock compiler and retained in
prior evidence; accepting it permits cross-target provisioning without executing
a target interpreter. Generating new startup artifacts/version pins remains
separate work.

Host choices construct declarations from a canonical explicit target prefix and
the existing full/install-only layout and ownership budgets. They package only
the two trusted helpers and the placeholder entry. They do not read the target
prefix, inspect an installed interpreter, install files or acquire a library.
Their report must state that host prerequisites are unverified; existing runtime
admission verifies the declared library/startup/source/cache bytes at execution.
No PBS artifact is required merely to declare these already pinned prerequisites.
This supports cross-target host declarations while keeping provider selection
explicit. Stock installation materialization, uv discovery and broader host
compatibility remain separate tasks.

Expose a narrow owned-template constructor under the runtime's portable
`packaging` facade. Return the admitted manifest, resource bytes and provenance;
stage those through `glue-pack`. The generated component remains `launch` and
entry `app/main.py`, with a fixed placeholder that raises an actionable error if
run directly. `build-python` replaces all placeholder app resources/identity and
entry while preserving runtime, target and non-app resources. Templates are build
inputs rather than completed applications.

Validate the full declaration/content map and all budgets before output creation.
Exclusively create a new output directory; reject existing directories, files or
symlinks without modification. Its parent must already exist. Write resource
files and provenance, then publish `manifest.json` last. No portable atomic
directory-rename guarantee is claimed. Publication I/O failure may leave a
partial newly created directory; do not remove unrelated paths or report success.
Input and output parent trees must remain stable during the operation, as for
ordinary builds. JSON stdout and retained provenance identify exact inputs,
resources, manifest identity and unverified host prerequisites.

Tests cover complete frozen identity, provider/profile equivalence, invalid
prefix/layout budgets, malformed/corrupt PBS inputs, deterministic templates,
unverified host declarations without discovery, publication protection and
placeholder replacement. Build the existing real installed-package fixture
through all three product-generated templates and replay the unchanged six-mode
runtime trace policy. Retain independent resource/provenance and build-process
checks plus cross-target Mac template creation. This does not close general
runtime/version selection, installation, package/native/platform compatibility
or distribution gates.
