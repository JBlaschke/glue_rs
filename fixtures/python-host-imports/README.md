# Archive source and resources with an installed host Python

This controlled GNU Linux arm64 fixture runs the same application/importer as
[the bundled source fixture](../python-imports/README.md), using explicit installed
paths for unchanged stock CPython 3.13.16 / PBS `20261009`. Its archive contains
18 app/helper/resource entries, with no runtime library, frozen bundle or stdlib.
Actual installed `importlib.resources` reads immutable archive assets.

Before Python loading, the launcher verifies the complete archive, closes it,
then verifies the host library and 69 reviewed stdlib sources. Six startup pins
remain unchanged; [63 supplemental pins](stdlib-import-pins.json) match the
independent complete PBS source inventory. All 12 relevant cache locations must
be absent. Symlinks, altered/missing sources and cached bytecode reject before
initialization. The host tree remains immutable and read-only through execution.
This verifies one dependency closure, not arbitrary installed Python packages.

The commands are:

```text
glue-python-bootstrap-probe prepare-host-imports FULL PREFIX OUTPUT.glue
glue-python-bootstrap-probe run-host-imports OUTPUT.glue
glue-python-bootstrap-probe run-host-imports-negative OUTPUT.glue app-error
glue-python-bootstrap-probe corrupt-host-imports INPUT.glue CORRUPT.glue
```

Preparation verifies the pinned upstream input and creates a new output. The
fixed installation layout is `PREFIX/lib/libpython3.13.so.1.0` and
`PREFIX/lib/python3.13`; selected paths need not exist on the preparing machine.
The opt-in `pbs-bootstrap` feature executes only on GNU Linux arm64. Other
targets reject before opening an archive. Version/build selection remains fixed
for this experiment.

With cached PBS inputs and the pinned image/toolchain available, run from the
repository root using new output directories:

```sh
sh fixtures/python-host-imports/run-linux.sh target/python-host-imports-validation \
  target/python-host-imports-validation-build
```

The harness builds/tests the unchanged C API revision 3, compares the shared
application under ordinary bundled loading, and prepares bounded installations
with only the selected sources and explicit host lures. It removes the producer,
headers and Cargo intermediates before running unprivileged in a separate
offline/read-only container without workspace access or a Python executable.
The seven complete traces cover success, app error, corrupt archive source,
wrong library, wrong/missing supplemental source and a nested bytecode cache.
Strict checking rejects source fallback, cache execution, unknown calls,
filesystem mutation attempts, additional processes and provider substitution.

The shared app checks import caching/reload, circular/relative imports, namespaces,
failed imports, virtual metadata, encoding cookies, binary/Unicode resources,
stream behavior and materialization rejection. Installed package/module and
bytecode lures must remain unused, including missing descendants of archive
packages and namespaces. A resource-reading `atexit` callback proves the Rust
context remains live during finalization. Stdout agrees exactly with the bundled
fixture's 100-byte PASS line.

App names that shadow built-ins, frozen aliases, bridge modules or stdlib roots
reject at index admission. [Runtime names](runtime-names.json) tie the built-in
and frozen inventories to the exact stock library; stdlib roots come from the
independent complete source inventory.

The [clean capture](../../docs/evidence/pbs-linux-arm64-host-imports-2026-10-10/README.md)
retains all seven host-import traces and fifteen bundled/startup regressions
from implementation `9aababa`, with source/input identities, exact manifests,
build provenance, validation logs and independently replayed compressed traces.

Product Python execution/discovery, native extension initialization, arbitrary
packages, general diagnostic source consumers and other versions/platforms
remain open. See [the decision](../../docs/decisions/0014-host-python-archive-imports.md).
