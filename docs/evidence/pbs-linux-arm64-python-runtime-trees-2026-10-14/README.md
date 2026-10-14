# Pinned installed Python runtime-tree evidence

Observed 14 October 2026. This is the existing GNU Linux arm64 CPython 3.13.16 /
PBS `20261009` install-only embedding profile, now prepared from selected installed
tree bytes. It does not establish general uv installation, native-package,
other-version/platform or release acceptance. See
[decision 0026](../../decisions/0026-python-installed-runtime-trees.md) and the
[fixture](../../../fixtures/python-runtime-trees/README.md).

Implementation `b8fdbd1`, physical-containment fix `801cbf6` and native fixture
staging `6b4499c` were merged as `a52424c`. The
[GNU source receipt](linux/source-revision.txt) binds a clean `6b4499c` capture;
[Mac receipt](mac/capture.json) binds clean `801cbf6`. All 87 Rust/C/header/Cargo
input identities are identical between both captures and merged main;
[validation attribution](checks/mac/python-runtime-trees-validation-inputs.json)
records these comparisons. The later fixture-only staging change is independently
covered by [current Mac controls](mac/current-fixture-controls/audit.json) and the
GNU capture. No failed development captures are included.

The immutable Linux image is `62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`.
The observed cell uses arm64, Linux `7.1.4-200.fc44`, glibc `2.36-9+deb12u10`,
GCC 12.2.0, strace 6.1, 4 KiB pages and Rust 1.88.0. See the
[environment](linux/environment.txt), [image identity](linux/image-inspect.json.gz),
[complete harness](linux/commands.sh), [console](harness.console.txt) and
[successful harness status](harness.exit-status.txt).

## Selected input and publication

Genuine uv 0.12.23 installs the exact pinned **unstripped** archive using an offline
custom catalog. Its actual binary, catalog, command, source identities and marker
checks are retained in [GNU installation provenance](linux/runtime-tree-installation.json),
[GNU catalog](linux/uv-download-metadata.json), [GNU command](linux/uv-install-command.json),
[Mac provenance](mac/uv-input/installation-provenance.json.gz) and the
[authenticated uv pins](../../../fixtures/python-runtime-trees/uv-pins.json).
This does not claim acceptance of uv's default catalog or stripped builds.

All 1,041 selected files are independently audited: the 73,563,968-byte shared
library, 1,037 sources and three stock encoding caches. The genuine uv source
matches a separately reconstructed 72-scalar sysconfig adjustment, with 27 root
substitutions. Product preparation verifies its entire exact spelling and reports
restoration of the original 51,570-byte stock source. The other 1,040 payloads
remain exact stock bytes. The output contains **89,479,393 selected bytes** in
1,041 files plus provenance, 103 directories, file mode `0444`, directory mode
`0555`, and mtime `1704067200`. See [GNU product report](linux/install-host.host-report.json),
[output audit](linux/install-host.host-tree-audit.json.gz) and
[Mac output audit](mac/host-audit.json.gz).

The product reads only the selected prerequisites. Unselected executables,
headers, aliases, markers, native modules and caches are outside inspection.
Tree reports set observed artifact/inventory/omission facts to null and distinguish
the upstream producer reference from an artifact actually inspected. Mac's
case-insensitive unselected terminfo contents are not claimed to be stock-equivalent.
Both input `bin` directories are removed before product preparation; the stock
fixture interpreter and uv perform separate build-time operations.

Both builders pass five valid preparations: genuine uv/repeat, stock selected
contents, quoted relocated uv root, and ignored unselected FIFO/native/cache
lures. Mac rejects 20 hostile commands; GNU rejects 19 and explicitly skips the
case-alias control on its case-sensitive native scratch filesystem. The Mac case
uses valid selected stock bytes and confirms rejection before publication.
Existing output file/directory/symlink sentinels and original selected bytes,
permissions and modification times are protected. Targeted clone tests additionally
check original inode and link-count preservation. See
[GNU controls](linux/runtime-tree-controls/audit.json) and
[Mac controls](mac/current-fixture-controls/audit.json). Fixture copies and cleanup
operate only on owned build-time scratch data.

## Complete process and runtime checks

The [complete verbose preparation trace](linux/install-host.host-process.trace.txt.gz)
passes the [independent process audit](linux/install-host.host-process-check.json).
It requires one process, one command and successful exit, all 1,041 bounded regular
reads/EOF/restats/closes before publication, no unselected payload access, no input
mapping or interpreter/network activity, and complete exclusive publication with
fixed modes/times. At most three input owners are live. The retained root descriptor
and both canonical output-parent ancestors have visible, distinct device/inode
identities before the first selected descendant is opened. This catches the observed Mac case alias and aliases exposing the retained
input-root identity in the output-parent ancestry. General mount topology, such as
a mounted input descendant whose logical ancestry hides the input root, is outside
this admission evidence; backing input/output trees must remain disjoint.

All [69 mutations of the actual trace](linux/install-host.host-process-hostile-controls.json)
reject, including missing/reordered/aliased identity checks, missing absence
preflight, invalid owners/flags/sizes/EOF, premature publication, extra input/output,
wrong modes/times, child/network activity and incomplete shutdown. The
[compressed replay](compressed-process-replay.json) and
[compressed hostile replay](compressed-process-hostile-controls.json) reproduce
all observations except the compressed trace's distinct byte identity. Trace strings
are limited to 512 bytes; complete SHA-256 identities come from independent file
audits, while the trace verifies visible prefixes and complete transfer semantics.

The existing three-provider real-package corpus is rebuilt through the product
CLI. All three Mac/GNU archive hashes are identical to each other and the
[prior real-package capture](../pbs-linux-arm64-python-real-packages-2026-10-14/README.md).
See [archive identities](capture-summary.json), [Mac build/product audits](mac/)
and [GNU product audits](linux/). Bundled, full-host and install-host runs each
produce the same exact 129 stdout bytes. Three first-entry CRC controls exit 1
before provider acquisition. All six complete runtime traces pass the unchanged
historical real-package policy, both raw and [compressed](compressed-runtime-replay.json).
Build inputs are removed; execution uses a read-only volume, uid/gid 65534, no
network, poisoned Python environment and inaccessible temporary/home paths.

| Validation | Passed |
| --- | --- |
| Mac/GNU source workspaces, Lua 5.4 / 5.5 | 489 / 490 plus all-target Clippy |
| Mac packaging workspace after containment fix | 533 plus all-target Clippy |
| GNU optimized Python / packaging / CLI | 154 / 63 / 22 plus all-target Clippy |
| Independent tree oracle, Mac/GNU | 24 |
| Independent process oracle, Mac/GNU | 15 |
| Existing Python trace policy suite, Mac/GNU | 253 |
| Existing adapter/importer/entry protocols | 32 / 16 / 7 |

Source workspace checks were recorded for `b8fdbd1`; all 85 participating
Rust/C/header/Cargo input identities remain unchanged. The two containment-fix
modules are absent from those source-only feature profiles and are covered by the
533/63 packaging checks and native trace/control evidence. Attribution and exact
counts are retained with [Mac checks](checks/mac/) and [GNU checks](checks/linux/).
The unchanged installed-package controls, requirement controls, templates,
inspection/verification/doctor/cat receipts and source/provenance records remain
under [GNU evidence](linux/).

`SHA256SUMS` covers every other retained file. Large traces/logs/JSON use
single-member gzip with deterministic timestamps; their complete decompressed
JSON identities are recorded in [compressed JSON identities](compressed-json-identities.json).
Large payload trees, native uv binaries and application archives are omitted.
Execution/helper/private loader/template bodies and historical policies remain
unchanged; this increment adds build-time selected-tree admission and evidence.
