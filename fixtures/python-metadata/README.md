# Python distribution metadata applications

This source-only profile exposes application-owned `.dist-info` through the
stock `importlib.metadata` APIs. It pairs with the existing pinned CPython
3.13.16 / PBS `20261009` bundled, full-host or install-only host provider on
GNU Linux arm64. Each new profile has its own build identity and exact metadata
helper; existing source profiles and importer bytes retain their identities.

The application exercises version/requirements, normalized distribution names,
plugin entry-point loading, namespace import-name mapping, RECORD file hashes
and reads, explicit Context path filtering and missing physical metadata. Its
listed file objects stay virtual and reject filesystem coercion/materialization.
Success prints:

```text
glue python distribution metadata ok: version=1.2.3 plugin=42 files=7
```

Run the portable adapter checks and the complete Linux fixture:

```sh
python3 fixtures/python-metadata/test_protocol.py
python3 scripts/test_linux_python_metadata_trace.py
sh fixtures/python-metadata/run-linux.sh
```

The harness stages inputs at build time, then removes the producer, headers and
staging files. The unprivileged runtime has a read-only Linux volume, no workspace
mount, disabled network and inaccessible temporary paths. Nine complete traces
exercise all three providers, traversal in otherwise integrity-valid RECORDs,
and corrupted stored metadata. Host installations contain physical metadata
lures that must remain invisible. Existing source-profile harnesses provide
separate regression evidence.

For manual packaging against an explicit install-only host prerequisite:

```sh
python3 fixtures/python-metadata/prepare.py install-host \
  fixtures/python-metadata/input target/metadata-stage \
  --prefix '/absolute/path/to/pinned Python installation'
target/debug/glue build --manifest target/metadata-stage/manifest.json \
  --root target/metadata-stage/root --output target/metadata-app.glue
target/debug/glue doctor target/metadata-app.glue
target/debug/glue run target/metadata-app.glue
```

Execution requires a `python-pbs` launcher built for the reviewed GNU Linux
arm64 cell. Full-host staging also takes `--base` with the original verified
bundled import archive; bundled staging takes only that base. The preparer
does not execute package code, install dependencies or produce the archive.
The product builder verifies declared resource identities. `doctor` checks
declarations/readiness; `run` additionally verifies metadata contents before
provider acquisition. Existing output paths are preserved.

The profile requires bounded canonical `.dist-info`, METADATA identities and
RECORD paths/ownership/hashes/sizes. It supports source modules and resources
within the existing application budgets, and exact canonical version spelling.
Generic wheel/venv ingestion, editable installs, `.pth`, external script paths,
`.egg-info`, version resolution and arbitrary native wheels remain pending.
See [decision 0021](../../docs/decisions/0021-python-distribution-metadata.md).
The [clean GNU Linux evidence](../../docs/evidence/pbs-linux-arm64-python-metadata-2026-10-13/README.md)
retains all nine metadata traces and 35 source-profile regressions, together
with independent payload and hostile-trace audits.
