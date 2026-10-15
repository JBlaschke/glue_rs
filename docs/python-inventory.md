# P03 Python environment inventory and archive imports

`python::inventory::collect` packages an ordinary project directory and the
resolved environment's installed package trees. Its output includes source,
metadata, ordinary package data, RECORD input identities, explicit omissions and
unowned files. Existing native images are returned separately for P04, without
recompilation or a duplicate source-archive copy. No manual provider template or
artificial application subtree is required.

`InventoryOptions` chooses a file, module or metadata console script. Configurable
defaults permit 100,000 scanned nodes and 1 GiB input bytes. RECORD parsing allows
100,000 rows / 16 MiB and verifies available SHA-256/size declarations. Original
RECORD bytes survive; no new ownership is fabricated. Generated environment bin
wrappers are reported as omissions. External RECORD data needs an explicit
mapping instead of silently escaping the environment. Pip and package data are
preserved by default. Pruning is explicit and reported.

Internal path-only top-level `.pth` directories become declared archive import
roots. Executable `.pth`, editable metadata and `.egg-link` inputs reject with a
remedy. Bytecode/cache, `.git`, known input environment, output and staging roots
are omitted before following links. Other internal symlinks are resolved safely;
escaping links and cycles reject. Build code never executes installation hooks.

The bounded Python importer verifies the glue header/manifest, ZIP inventory and
every resource's size/SHA-256 before returning bytes. It implements source import
caching, separate import roots, namespace portions, metadata/entry points,
`pkgutil.get_data`, and read-only `importlib.resources` streams/traversal. Source
origins use `glue:///...`. Archive `as_file` rejects explicitly; no temporary
resource file is created. Native module routing delegates to stock
ExtensionFileLoader and is populated by P04.

The `fixtures/mvp/python-env` corpus runs through a host interpreter in the P03
focused test after the complete project and environment inputs are removed. This
is explicitly a host-importer execution test; bundled provider acceptance is P02.
It exercises split namespace imports and namespace resource listing, metadata,
package resources, repeated imports, argv and extraction rejection. Static tests
cover native handoff, unowned data, path-only/executable `.pth`, RECORD mismatch
and symlink escape. The host corpus ran on macOS arm64 PBS 3.13.16 and 3.14.5.

```sh
GLUE_TEST_PYTHON=/supplied/bin/python3.13 cargo test -p glue-pack \
  --features python --test python_inventory -- --include-ignored
```

P05 supplies real ordinary/uv environment and provider matrix receipts. A passing
fixture alone does not claim every installed package, wheel or platform works.
