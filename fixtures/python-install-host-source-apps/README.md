# Pinned stock install-only host Python source applications

This separate profile runs source applications with the exact unstripped
CPython 3.13.16 / PBS `20261009` install-only distribution on GNU Linux arm64.
The selected provider supplies 1,037 sources (15,894,268 bytes), the pinned
library and three stock encoding caches. The existing full-source host profile
keeps its own 2,174-source and cache-absence requirements.

The ordinary helper verifies the complete cached install-only artifact before
parsing or writing an installation. It copies all 3,478 regular files and 1,048
symlinks, preserves the stock source/cache bytes and normalized mtimes, and
records its read-only mode transformation. The complete installation contains
case-distinct terminfo entries; materialization requires a case-sensitive
filesystem, such as the Linux filesystem used by the Podman harness.

```sh
# Run installation preparation on a case-sensitive filesystem.
python3 fixtures/python-install-host-source-apps/prepare.py install \
  /absolute/path/to/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz \
  /absolute/path/to/host-python --provenance target/stock-host-provenance.json

# Staging does not require a runtime archive or installed provider.
python3 fixtures/python-install-host-source-apps/prepare.py stage \
  /absolute/path/to/my-application target/install-host-report-inputs \
  --prefix /absolute/path/to/host-python \
  --app-id my.report --entry app/tasks/report.py --component report

GLUE_PYTHON_INCLUDE_DIR=/absolute/path/to/include/python3.13 \
  cargo build --locked -p glue-runner --features python-pbs
target/debug/glue build --manifest target/install-host-report-inputs/manifest.json \
  --root target/install-host-report-inputs/root --output target/install-host-report.glue
target/debug/glue verify target/install-host-report.glue
target/debug/glue doctor target/install-host-report.glue
target/debug/glue run target/install-host-report.glue
```

Staging works on Mac. Execution requires the reviewed GNU Linux arm64 cell and
matching verified headers at launcher build time. The app contract shares the
existing host profile's entry, import, resource and archive limits; the archive
contains only the original pinned importer and application files. Build and
doctor admission check declarations without acquiring the selected installation.
The helper neither downloads providers nor executes app code.

Before initialization, all selected sources become verified owned bytes. The
three exact stock cache files must be present in a closed encoding cache
directory; other derived cache directories and startup shadows reject. Cache,
startup and directory owners stay live through finalization, while individual
snapshot source descriptors close promptly. All expanded paths must fit 4,096
bytes, directory owners must fit 256, and total retained owners must fit 763.

Stock cache headers name a timestamp different from the normalized source
mtime. The runtime matrix captures the resulting cache probes and source
fallback. After initialization, the unchanged trusted prelude removes default
filesystem import fallback and the shared importer serves later sources and
resources from owned bytes with virtual origins. Initialized host/frozen modules
retain their stock metadata.

The full physical stock installation includes an interpreter, headers, native
files and other data. This source profile verifies its selected library/source/
cache prerequisites; it does not certify every installed file or expose
arbitrary site-packages/native modules. The installed paths must remain immutable
and read-only through execution/finalization; mapped library backing must remain
immutable for process life. Trusted app code retains host I/O and can change
import machinery. This is not a sandbox or general package compatibility claim.

From Mac, run the offline Podman matrix:

```sh
sh fixtures/python-install-host-source-apps/run-linux.sh
python3 -B -m unittest discover -s scripts \
  -p test_linux_python_install_host_source_app_trace.py
```

The harness uses an ephemeral Linux volume to preserve every case-distinct
stock member. Build inputs are copied into that volume, then removed before
runtime. The runtime container is unprivileged and read-only, without workspace
or the separate producer/build inputs, with poisoned environment, empty working
directory and unavailable temporary paths. The complete selected stock provider
remains installed, including its ordinary executable and headers.

Sixteen traced invocations pair the existing apps with stock startup and nine
damaged-host controls. Sixty exact product controls also include rejection of
the old full-source profile against this stock installation. Before removing the
volume, an independent post-runtime audit rechecks all ten installed trees
against the pinned complete artifact and declared fixture changes, including
regular bytes, symlink targets, mtimes and read-only modes. Only launcher/archive
bytes are exported onto the Mac filesystem; provider integrity proof stays in
the retained audit/provenance receipts.

See [decision 0019](../../docs/decisions/0019-install-only-host-python-source-apps.md)
for the profile's admission, ownership and remaining scope.

The [clean evidence bundle](../../docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains all 16 new cases and 61 fresh regressions from `7a8e32c`, all compressed
replays, 60 exact new controls and 894 rejected hostile edits. Complete provider
audit and Linux-volume cleanup receipts accompany the exported artifact hashes.
