# Pinned explicit-host Python source applications

This optional source profile runs application-owned scripts, modules and assets
with an explicitly selected stock CPython 3.13.16 / PBS `20261009` installation
on GNU Linux arm64. It shares the bundled source-app entry/import/resource
contract and keeps provider selection explicit.

The runtime prefix supplies the exact shared library and full pinned projection
of 2,174 sources (39,158,056 bytes). The install-only distribution contains only
1,037 of them; this profile requires the full projection. Build-time preparation
can materialize it from the verified controlled bundled runtime archive described
by the [bundled import fixture](../python-imports/README.md).

```sh
# Prepare the exact host prerequisites at a new absolute prefix.
python3 fixtures/python-host-source-apps/prepare.py install \
  /absolute/path/to/bundled-imports.glue /absolute/path/to/host-python \
  --provenance target/host-input-provenance.json

# Stage only app sources/assets and the pinned shared importer into the archive.
python3 fixtures/python-host-source-apps/prepare.py stage \
  /absolute/path/to/bundled-imports.glue /absolute/path/to/my-application \
  target/host-report-inputs --prefix /absolute/path/to/host-python \
  --app-id my.report --entry app/tasks/report.py --component report

GLUE_PYTHON_INCLUDE_DIR=/absolute/path/to/include/python3.13 \
  cargo build --locked -p glue-runner --features python-pbs
target/debug/glue build --manifest target/host-report-inputs/manifest.json \
  --root target/host-report-inputs/root --output target/host-report.glue
target/debug/glue verify target/host-report.glue
target/debug/glue doctor target/host-report.glue
target/debug/glue run target/host-report.glue
```

The helper verifies its base inputs and never downloads or executes app code.
The ordinary builder admits the profile before looking up input resources and
does not inspect the selected runtime installation. Packaging works on Mac;
execution requires the reviewed GNU Linux arm64 target and matching verified
headers at launcher build time. Prefixes are canonical absolute ASCII paths;
every expanded source/cache path and the 256 distinct directory-owner budget
must fit the profile before acquisition.

At runtime the archive verifies and closes before host access. The library and
all pinned source files verify before Python loads. Derived cache locations
must be absent; missing/changed/symlink sources and startup native/bytecode
shadows reject. Snapshot sources become owned immutable bytes with bounded
descriptor use. The installation and startup paths must stay immutable and
read-only; source hashes and open descriptors do not freeze mutable backing
files.

Host startup still uses its installed encodings. A trusted prelude then clears
ordinary filesystem import paths and removes `PathFinder` before installing
the unchanged shared source importer. Later modules resolve from verified
snapshot bytes with virtual `glue://` origins; already initialized startup and
frozen modules retain their stock metadata. Extra host files cannot become
ordinary import fallbacks. Trusted application code retains host I/O and can
change import machinery; this is an import compatibility profile, not a sandbox.

The archive owns only the importer and `app/` files. Imports live below
`app/python/`; the declared `.py` entry and assets may live elsewhere below
`app/`. Limits stay 1,024 app files, 8 MiB combined, 4 MiB per file and 64 KiB
for the entry. The host archive has a 16 MiB archive/total bound and a 1 MiB
manifest bound. Runtime/stdlib names, unsupported source layouts, bytecode and
native payloads reject. The source resolver does not expose arbitrary
site-packages or nonidentifier configuration modules merely because their
bytes are pinned.

Entries run as `__main__` with virtual filename/argv and the same bounded
status-1 exception contract, including `SystemExit(None)` and `SystemExit(0)`.
No app arguments, `-m` entry or full traceback rendering are supplied. Source
and resource callbacks stay live through finalization. Filesystem materializing
resource helpers reject; read-only streams and byte/text reads are supported.

From the Mac, run the offline Podman fixture:

```sh
sh fixtures/python-host-source-apps/run-linux.sh
python3 -B fixtures/python-host-source-apps/test_protocol.py
```

The fixture pairs the existing bundled apps with the new host provider, exercises
additional stdlib imports/resources and finalization, and rejects corrupt app
bytes plus damaged unused host sources, deep caches, startup shadows and a
missing library. Its separate strict checker leaves historical policies
unchanged. Runtime containers are unprivileged/read-only, without the workspace
or build/producer/header tools, with poisoned environment, empty working
directory and unavailable temporary paths.

See [decision 0018](../../docs/decisions/0018-host-python-source-apps.md) for
ownership, startup prerequisites and the remaining compatibility scope.
