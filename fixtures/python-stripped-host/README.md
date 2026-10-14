# Pinned stripped install-only host fixture

This fixture covers the official conventional-GIL CPython 3.13.16 / PBS
`20261009` GNU Linux arm64 `install_only_stripped` image. `pins.json` records its
independent compressed artifact and library identities, loader header, program
headers and build ID. The original source and cache inventories remain bound to
the unstripped producer; the new image has its own provider identity.

The official stripped artifact is 29,327,967 bytes with SHA256
`52c6993abd6ac687cceb787ecee83b166271bc06ad80ac9cac82c5d28d3c00bc`.
Its library is 22,177,832 bytes with SHA256
`327af7e7114d339222b4fa8af954207c78a3b382f1edda667f16a48c89dfaf75`.
The cached primary GitHub release JSON and upstream `SHA256SUMS` independently
declare the same compressed pin.

`inspection.py` reads both authenticated gzip tar streams without installing or
executing them. It compares all 4,526 paths, types, modes, times, owners and link
targets: 3,478 regular files and 1,048 symlinks. Fifteen regular records change:
nine ELF binaries/libraries and six same-sized pip PE launcher files. The entire
regular payload drops from 182,155,939 to 79,291,731 bytes. All 1,037 selected
stdlib sources and three selected encoding caches retain their previous exact
identities (15,915,425 bytes).

The independently decoded library ELF has identical eight program headers,
25 allocated sections including symbol version tables, dynamic entries and
dependencies, SONAME, GNU build ID, and all 29 selected embedding API exports.
Its first load segment changes only six ELF header bytes, at offsets 40, 41,
42, 43, 60 and 62, recording the reduced section table. Its second load segment
is byte-identical. Ten nonallocated debug sections disappear. These static facts
support reusing the existing bridge; actual GNU execution is recorded separately
by the runtime harness.

Reproduce the data inspection with the cached official inputs:

```sh
python3 -I -S -B fixtures/python-stripped-host/inspection.py \
  --original target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz \
  --stripped target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz \
  --output target/new-paired-stripped-inspection.json
```

`prepare.py extract-tree --pbs-install-only ARTIFACT --output NEWROOT --audit
NEWJSON` creates a selected stock tar projection containing exactly 1,041 files
and 38,093,257 payload bytes. It extracts no interpreter, uv, headers or other
unselected input. This projection exercises selected installed-tree ingestion;
it is not evidence of a genuine uv installation or uv's default catalog.

Other independent helper commands are:

```text
prepare.py audit-input --runtime-tree ROOT --output NEWJSON
prepare.py audit-output --prefix PREFIX --report REPORT --output NEWJSON [--runtime-tree ROOT]
prepare.py controls --glue GLUE --pbs-install-only STRIPPED --unstripped-artifact ORIGINAL --runtime-tree ROOT --output NEWDIR [--scratch-parent DIR]
```

Omit `--runtime-tree` when auditing publication from an artifact. Audits compare
every output byte, the exact report/provenance schema, and nanosecond file and
directory times plus modes. Reports preserve the original producer inventory
identities and distinguish complete tar inspection from selected tree inspection.
The input audit includes exact bounded file prefixes for independent syscall
replay; it does not certify an entire installation.

The controls require four successful preparations (artifact, tree, identical
repeat and ignored unselected interpreter/native/FIFO lures) and 20 rejections
when the original artifact is supplied. They exercise missing/corrupt/oversized
library, missing/corrupt cache, modified sysconfig, leaf/ancestor links, FIFO,
opposite provider/artifact, duplicate/mixed inputs, relative roots, overlap, and
existing file/directory/link preservation. Controls copy one fixture-owned
selected base into native scratch storage before creating aliases and special
files. They verify the genuine source bytes, inodes, link counts, modes and times
are unchanged and delete only their owned scratch trees.

Run the independent hostile-oracle unit suite with:

```sh
python3 -I -S -B fixtures/python-stripped-host/test_prepare.py
```

The GNU harness, minimal app, runtime trace checks and CRC/missing/wrong-image
controls are maintained separately in this directory. Existing provider fixtures
and policies are preserved.

`test_process.py` privately reuses the historical closed selected-tree ownership
and publication graph. Its stripped tree contract binds the exact new provider,
input/output inventories and full report bytes. The artifact adapter admits one
compressed input descriptor, exactly two complete bounded read/EOF passes with
their two rewinds, then its close before any publication. Artifact publication
uses its existing exclusive creation; tree ingestion additionally has the early
no-follow output absence and physical overlap preflight. Both graphs reject
children, network, foreign input reads, input/output mappings and mutations
outside the owned output. A `-s512` trace binds visible byte prefixes and transfer
totals; full SHA256 identities come from the independent input/output audit.

Process replay takes `--trace`, `--program`, `--prefix`, `--report`, and either
`--artifact` or `--runtime-tree` with `--input-audit`. `--artifact-file` permits
replay against the same authenticated cached bytes when the recorded mount path
is unavailable locally. `--hostile-controls` rejects mutations of the captured
complete trace (69 tree controls and 21 artifact controls). Twenty preparation
oracle unit tests and 23 process oracle unit tests cover concrete hostile cases;
the preparation suite also checks fresh evidence/build guard preservation before
any external build tool runs.

Run the native fixture from a clean feature commit, using the pinned Podman image
and cached, authenticated upstream inputs:

```sh
sh fixtures/python-stripped-host/run-linux.sh
```

Build-time staging is separate from runtime acquisition. The harness removes the
producer, headers, selected input and application staging, then runs the relocated
launcher from a read-only volume as uid/gid 65534 with network disabled and private
inaccessible temporary/home directories. The same minimal application checks
isolated startup, hashlib/decimal/json, archive distribution metadata, a package
resource and resource access during finalization through both images. Exact output
is in `expected.stdout.txt`. Missing, opposite-sized, same-sized corrupt libraries,
an opposite image/profile and first-entry CRC corruption reject before startup.
A separate actual old-image preload capture checks the existing explicit
`LD_PRELOAD` refusal; it does not establish protection from arbitrary injection.

The new runtime checker creates an isolated historical policy graph per check.
It binds the exact five application resources, two unchanged helpers, provider,
target, archive inventory/offsets and captured stdout/stderr to inspected bytes.
Identical load geometry is retained; only the selected library size/header changes.
The observed hashlib operations have closed guards: fourteen ordered wake calls at
fixed words within the pinned image and one empty `/dev/null` configuration stream
with exact owner, character-device identity, operation sequence and phase. They are
absent from rejection cases. No external configuration path or arbitrary futex is
admitted. Eleven independent checker tests and 350 actual-trace mutations cover
these boundaries. Existing provider policies remain unchanged.
