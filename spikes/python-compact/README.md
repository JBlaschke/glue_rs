# P00: stock Python compact bootstrap

Executable build-time experiment, not the product adapter. It never fetches,
installs or rebuilds a runtime/module. Run with a local Unix CPython tree:

```sh
python3 spikes/python-compact/build.py --python /supplied/bin/python3.13 \
  --output '/tmp/python compact'
python3 spikes/python-compact/test_recipe.py --python /supplied/bin/python3.13 \
  --receipt /tmp/python-compact-receipt.json
```

The selected interpreter's isolated metadata probe is bounded to 15 seconds and
64 KiB aggregate output. The tree inventory is limited to 50,000 files / 2 GiB.
This spike rejects framework, debug and free-threaded builds with an explanation.
There is no upper minor-version ceiling or content-digest admission list.

## Interface handed to P02

```text
runtime/bin/pythonX.Y
runtime/lib/pythonXY.zip              # source stdlib plus data, no site-packages
runtime/lib/pythonX.Y/lib-dynload/*    # supplied native stdlib modules
runtime/lib/...                      # supplied runtime native libraries
support/python-bootstrap.py          # exactly one loose source bootstrap
app.zip                              # tiny application/archive-import fixture
launch.json                          # recipe metadata; not the product manifest
```

The ZIP is a CPython startup prefix landmark. Neither a loose `os.py` nor loose
`encodings` source files are needed in the tested PBS builds. Preserve the
interpreter's `bin` / `lib` relationship. Empty native-stdlib directories are
created at build time. All native input bytes are copied unchanged.

PBS 3.15.0b1 freezes `encodings`, whose package search path still points at the
loose stdlib. Additional codecs such as `cp437` then fail, breaking ZIP metadata
reads. The bounded bootstrap detects a frozen `encodings` package and points its
child-module path at `pythonXY.zip/encodings`; no version-number condition or
runtime-byte change is required. This was necessary for the 3.15 corpus.

The launcher resolves paths relative to the distribution, then invokes directly:

```text
<root>/runtime/bin/pythonX.Y -I -S -B <root>/support/python-bootstrap.py \
  <root>/app.zip compact_probe [application arguments...]
```

Resolve every path before changing cwd; do not execute the relative `launch.json`
argv literally from arbitrary cwd. In the product `RuntimeLaunchSpec`, use
`{root}/support/python-bootstrap.py`, `{archive}`, then entry mode and entry
selection. Clear inherited environment, inherit stdio, forward signals and wait
for the interpreter. No `PYTHONHOME` or `PYTHONPATH` is needed. The bootstrap
validates startup paths before installing app imports. `-I -S -B` blocks site,
`.pth`, user-site, inherited Python settings and bytecode cache writes.

P02 must replace the fixture ZIP importer with the product archive importer and
resource adapter. The spike uses stock ZIP `importlib.resources` streams and
metadata; it does not implement product `as_file` rejection. It inventories native
files within the supplied prefix, but intentionally leaves full closure checking
to C03/C04. Tcl/Tk external data is not assembled or claimed to work.

## Execution observations (macOS arm64, 15 October 2026)

| Supplied runtime | Result |
| --- | --- |
| uv/PBS CPython 3.13.16 | Relocated isolated archive startup and corpus passed |
| uv/PBS CPython 3.14.5 | Relocated isolated archive startup and corpus passed |
| uv/PBS CPython 3.15.0b1 | Relocated isolated archive startup and corpus passed |
| Homebrew CPython 3.14.8 framework | Rejected: absolute framework dependency requires explicit edits |
| python.org CPython 3.15.0 framework | Rejected: absolute framework dependency requires explicit edits |

The supplied installation is copied to a controlled input prefix, built, then
that entire input prefix is removed. The distribution moves to a path with spaces
and `é`, becomes read-only, runs from empty cwd with empty PATH, invalid HOME and
temp/cache paths, and poison PYTHONHOME/PYTHONPATH. Checks include encodings,
math/ssl, metadata, source/resource reads and deployed `_dbm`. In these PBS builds
math, `_ssl` and `_sqlite3` are built into the executable; `_dbm` is a real shared
module. The per-runtime JSON receipts are external logs and are not committed.

This is a startup proof, not the full no-extraction gate: no process-tree syscall
trace or network isolation ran. macOS `sandbox-exec` failed with `sandbox_apply:
Operation not permitted` under this execution environment. No Linux runner was
available. V02/R02 must supply those observations; the script reports these gaps.

For non-PBS macOS framework builds, a feasible layout keeps the framework version
root as `runtime/`, including its `Python` image, executable and native module
closure. `otool -L` showed these exact executable dependencies:

```text
Homebrew: /opt/homebrew/Cellar/python@3.14/3.14.8/Frameworks/Python.framework/Versions/3.14/Python
python.org: /Library/Frameworks/Python.framework/Versions/3.15/Python
```

P02 subsequently proved that framework `bin/pythonX.Y` may be a stub which execs
an original-prefix app executable. Select the existing real interpreter at
`Resources/Python.app/Contents/MacOS/Python`, preserving that path under runtime.
Its Python-image dependency becomes `@executable_path/../../../../Python`;
collect and rewrite other non-system absolute edges using actual loader-relative
paths. Re-sign every modified Mach-O and verify the final signatures. No such
normalization is silently performed here, and no non-PBS relocation success is
claimed. A non-framework POSIX installation with relative native edges can use
the same ZIP landmark recipe; that route still needs native-run evidence.

P05 later proved a smaller final framework layout: the same real app executable
can deploy as standalone `runtime/bin/Python`, with its core edge explicitly
normalized to `@loader_path/../Python`. Relocated isolated execution and strict
signature verification pass without retaining an incomplete `.app` container.
This product-provider improvement does not change the spike's historical results.
