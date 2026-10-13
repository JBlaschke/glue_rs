# Build-time archive packaging

The default API packages exactly an explicit manifest's inventory under an
input root. It verifies identities and the generated archive before creating
the output, and never overwrites an existing file. `build_owned` provides the
same publication and integrity checks for bounded owned payloads.

The optional `python` feature adds an installed-package adapter. It preserves
an admitted metadata-profile provider template and combines it with the `app/`
subtree of an application input and a complete source-only site-packages tree.
`PackageInput::Venv` reads conventional Python 3.13 configuration to locate that
tree; `SitePackages` selects it directly. The adapter executes no interpreter,
installer, activation hook or package code.

Each retained package file requires a RECORD owner. Original hashes and sizes
verify before deterministic RECORD rewriting. Purelib WHEEL declarations,
metadata identities, closed ownership and the runtime's app/module/path policy
all validate before publication. Bytecode and recognized generated wrappers
are omitted and reported; native filenames, editables, `.pth` hooks, arbitrary
traversal, missing/unowned files, symlinks and collisions reject. The caller must
keep input trees stable during reads, as for ordinary builds.

Reports include relative input identities, distributions, original RECORD
identities, omissions and final manifest/archive hashes. They do not resolve
dependencies or prove general compatibility. Existing application caps and
explicit scan limits (4,096 entries, 1,024 directories, depth 32 across app and
package trees) bound normalization. A venv containing build tools may exceed
those limits; nothing is implicitly pruned.

The runner exposes this API with `--features python-pack` and `glue build-python`;
`python-pbs` includes packaging and the existing opt-in GNU execution route.
See [decision 0022](../../docs/decisions/0022-python-installed-package-ingestion.md)
and [the offline fixture](../../fixtures/python-venv-ingestion/README.md).
