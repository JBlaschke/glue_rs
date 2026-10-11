# Pinned bundled Python source applications

The optional product runner admits application-owned source and assets with
stock CPython 3.13.16 / PBS `20261009` on the observed GNU Linux arm64 profile.
Application IDs, component names and entry scripts can vary. Runtime, frozen
startup, archive importer and all 2,174 stdlib sources remain pinned.

An application input directory contains its declared entry below `app/`,
importable modules/packages below `app/python/`, and assets below `app/`.
For example:

```text
my-application/
  app/tasks/report.py
  app/python/report_data/__init__.py
  app/python/report_data/answer.py
  app/python/report_data/assets/message.txt
```

Stage inputs from an already prepared, verified `stock-pbs-archive-imports`
runtime archive. The existing [bundled import fixture](../python-imports/README.md)
documents its pinned producer and preparation. The portable staging helper
reads and verifies those stock resources, copies the application inventory,
and emits a manifest/input root. It does not run application code or download
inputs. Keep build inputs stable during preparation and packaging.

```sh
python3 fixtures/python-source-apps/prepare.py \
  /absolute/path/to/bundled-imports.glue /absolute/path/to/my-application \
  target/report-inputs --app-id my.report --entry app/tasks/report.py

# Enable the admitted packaging policy; on GNU Linux arm64 also supply the
# independently verified pinned header tree when building this launcher.
GLUE_PYTHON_INCLUDE_DIR=/absolute/path/to/include/python3.13 \
  cargo build --locked -p glue-runner --features python-pbs
target/debug/glue build --manifest target/report-inputs/manifest.json \
  --root target/report-inputs/root --output target/report.glue
target/debug/glue verify target/report.glue
target/debug/glue doctor target/report.glue
target/debug/glue run target/report.glue
```

Packaging with this feature also works on macOS; execution requires the
reviewed GNU Linux arm64 target. The helper's inventory is explicit in the
generated manifest; `glue build` consumes only those files. The builder admits
the source profile before input-root lookup and widens its member bound only
for this pinned runtime. Lua and unrelated build limits remain unchanged.

The entry runs as `__main__`, with virtual `__file__` and one virtual `sys.argv`
entry. Source encoding cookies and binary resource streams are preserved.
No app arguments or module `-m` entry are provided. Uncaught exceptions,
including `SystemExit(None)` and `SystemExit(0)`, use the existing bounded
message/status-1 contract; full traceback rendering remains separate work.
Resource materialization helpers reject; streams and buffer reads are supported.
User code retains ordinary Python capabilities; this is not a sandbox.

Application limits are 1,024 resources, 8 MiB combined, 4 MiB per resource and
64 KiB for the entry. Schema-zero resource paths remain portable ASCII; spaces
and other admitted filename characters are preserved in virtual origins.
Bytecode/cache/native paths, ambiguous or unsupported module layouts, and
app imports shadowing pinned runtime/stdlib names reject. Host runtime and
native extension declarations remain confined to their earlier exact fixtures.

Run the offline Linux fixture from the Mac using the pinned Podman image:

```sh
sh fixtures/python-source-apps/run-linux.sh
python3 fixtures/python-source-apps/test_entry.py
python3 -m unittest discover -s scripts -p 'test_linux_python_source_app_trace.py'
```

The fixture exercises independent app IDs/entries, modules, packages,
namespaces, encoding, resources, finalization reads, real application/compiler
errors and pre-loading corruption rejection. Complete traces bind commands,
readiness, archive reads, runtime memfd writes/seals/mapping, exact output and
descriptor lifetimes. The strict source-app policy is separate from the
unchanged historical checkers. Runtime containers are offline, unprivileged,
read-only, without a workspace mount, with an empty working directory and
unavailable temporary paths after producer/header/build removal.

See [decision 0017](../../docs/decisions/0017-bundled-python-source-apps.md)
for admission, ownership and remaining compatibility scope.
The [clean capture](../../docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
retains all six source-app and 42 regression traces from `d3ddac3`, with passing
compressed replays, 34 exact source-app CLI controls and 198 rejected hostile
source-app edits. The default harness required a clean implementation checkout;
the retained development opt-in is `false`.
