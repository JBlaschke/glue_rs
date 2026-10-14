# Pinned real pure-Python packages

This bounded GNU Linux arm64 / CPython 3.13.16 workload uses the unmodified
[markdown-it-py 4.2.0](https://pypi.org/project/markdown-it-py/4.2.0/),
[mdit-py-plugins 0.6.1](https://pypi.org/project/mdit-py-plugins/0.6.1/) and
[mdurl 0.1.2](https://pypi.org/project/mdurl/0.1.2/) wheels committed under `wheels/`.
`wheel-pins.json` records exact published artifact hashes and source URLs. The
fixture never rewrites upstream sources, assets, metadata or licenses. Optional
extras, native packages and other versions remain outside this corpus.

Prepare with the matching stock PBS producer, using its pip to install offline
into a fresh conventional venv created with `--without-pip`:

```sh
/absolute/producer/bin/python3.13 -I fixtures/python-real-packages/prepare.py install \
  /absolute/producer /absolute/new-installed-input
```

The helper verifies complete upstream wheel identities and RECORD ownership,
then every installed payload against its wheel. Default pip compilation produces
110 source caches; their ownership, magic, timestamp/size headers and observed
hashes are audited. The single generated `markdown-it` wrapper is hashed and
omitted. Pip is not installed into the venv. The retained projection has 151
package files plus `app/main.py`; only each installed RECORD is rewritten, in
sorted LF-terminated CSV form with the cache/wrapper rows removed and its own
hash/size blank. `INSTALLER` and `REQUESTED` remain.

Output contains `application/`, `venv/`, independently normalized
`expected-input/`, `expected-inventory.json`, `installation-provenance.json` and
complete command/stdout/stderr/status receipts. The exact same application then
runs under ordinary pinned Python. Its 129-byte success line matches the archive
application. The fixed full HTML and token serialization are committed in
`expected-workload.json`; hashes are asserted by the app. Fixture hashing uses
CPython's reviewed built-in `_sha2`, avoiding unrelated OpenSSL initialization.

The app exercises CommonMark rendering and tokens, Unicode URL encoding,
front matter, footnotes and task lists. It checks real distribution versions,
Python requirements, dependencies, RECORD files, loaded console entrypoint
`--version`, package streams, typed markers and preserved package/distribution
licenses. Archive-only assertions check virtual diagnostic origins, reject
filesystem coercion/materialization, and exclude physical metadata lures.
Ordinary Python's generated caches/wrapper are filtered when comparing retained
metadata inventories; virtual resource checks are skipped only in the explicit
stock-baseline mode. No package code is changed for those checks.

Build each prepared provider template through the product, then independently
audit the complete resulting archive and build report:

```sh
glue build-python --provider-template /absolute/template/manifest.json \
  --provider-root /absolute/template/root --app /absolute/new-installed-input/application \
  --venv /absolute/new-installed-input/venv --app-id python.real-packages \
  --entry app/main.py --output /absolute/application.glue --json > build-report.json
python3 -B fixtures/python-real-packages/prepare.py audit-build \
  build-report.json /absolute/application.glue \
  --provenance /absolute/new-installed-input/installation-provenance.json
```

The independent oracle verifies all selected original input/RECORD identities,
exact omissions, every normalized application and provider resource, ZIP member
bytes/compression, framing and reported archive hashes. It imports no product
API and executes no interpreter during projection or auditing. Portable Mac
building/projecting uses a copied GNU installed tree with its venv interpreter
removed. `project VENV NEW-OUTPUT` rechecks ownership and emits the same projection.

Run the fixture controls and fresh six-mode offline native matrix:

```sh
python3 -B fixtures/python-real-packages/test_prepare.py
sh fixtures/python-real-packages/run-linux.sh
```

The matrix covers three providers and three damaged-entry controls with complete
traces on immutable relocated storage. Its isolated policy retains archive,
readiness, loader, snapshot/cache, descriptor, process, network and no-extraction
checks. This is evidence for these packages and this cell, rather than general
package/platform compatibility or a sandbox claim. See
[decision 0025](../../docs/decisions/0025-python-real-package-compatibility.md).
The [clean Mac/GNU evidence](../../docs/evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md)
retains all six complete runtime traces, independent build/requirement controls,
source bindings and compressed replays.
