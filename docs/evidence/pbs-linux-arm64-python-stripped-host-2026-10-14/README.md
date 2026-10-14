# Pinned stripped Python host evidence

Controlled GNU Linux arm64 observation, 14 October 2026, from clean feature commit
`aef2f71af60b8f96b289af6cba6328763817a52f` on `codex/a7-python-stripped-host`.
The implementation is described in [decision 0027](../../decisions/0027-python-stripped-host-runtime.md)
and the [reproducible fixture](../../../fixtures/python-stripped-host/README.md).
The branch also retains the preceding runtime-tree evidence commit `421b24f`.

The separate `host-install-stripped` metadata profile admits the official
conventional-GIL CPython 3.13.16 / PBS `20261009` GNU Linux arm64 stripped image.
Its library is 22,177,832 bytes, SHA256
`327af7e7114d339222b4fa8af954207c78a3b382f1edda667f16a48c89dfaf75`, compared with
73,563,968 bytes for the original unstripped image. The selected prerequisite
tree has 1,041 files and 38,093,257 payload bytes. Each profile rejects the
opposite library; existing bundled, source-only and native-extension image
identities remain unchanged.

The [primary upstream receipt](inspection/upstream-receipt.json),
[paired inspection](mac/paired-inspection.json) and complete compressed
[original](inspection/unstripped-inventory.json.gz) /
[stripped](inspection/stripped-inventory.json.gz) inventories authenticate the
29,327,967-byte stripped artifact. All 4,526 path/type/mode/time/owner/link records
match; fifteen regular payload identities change. All 1,037 sources and three
startup caches retain their exact original pins. Eight program headers, 25
allocated sections, dynamic dependencies/version tables, GNU build ID and 29
embedding API exports match. Only six section-table header bytes change inside
the first load segment; the second is byte-identical. This reduces storage size,
without a claim of reduced mapped runtime memory.

Mac and GNU each pass four valid preparations and twenty rejection controls.
Independent audits verify every selected input/output identity, exact provenance,
0444/0555 permissions and nanosecond timestamps. Unselected interpreter/native/
FIFO lures are ignored. Missing, corrupt, oversized, linked, FIFO, opposite-image,
option, relative-root, overlap and existing-output cases reject. Original input
bytes, inodes, link counts, modes and times remain unchanged. See the complete
[Mac controls](mac/controls/summary.json) and
[GNU controls](linux/preparation-controls/summary.json).

Two complete native preparation traces validate ownership and publication order.
The [artifact audit](linux/stripped.prepare-process-audit.json) checks one process,
two complete compressed reads/EOF/rewind passes totalling 58,655,934 bytes, and
input closure before publication. The
[tree audit](linux/stripped-tree.prepare-process-audit.json) checks all 1,041
complete reads/EOF/restats/closes, early root/output overlap identity checks and
at most three live input owners. Both publish 1,042 files including provenance
and freeze 103 directories; no child, network, foreign input, input mapping or
outside-output mutation is admitted. A 512-byte trace window binds visible
prefixes and complete byte counts; independent file audits supply full hashes.
All 21 artifact and 69 tree mutations reject. Their
[compressed replays](replays/preparation-compressed-replay-summary.json) reproduce
the raw results, excluding only compressed trace identity.

The same minimal application runs with both images and prints exactly:

```text
PASS python-host stdlib=hashlib,decimal,json metadata=1.0 resource=42
```

It checks isolated startup, stdlib behavior, archive metadata/resources and
resource access during finalization. Five runtime controls reject before startup:
missing library, opposite-sized library, same-sized hash corruption, opposite
profile/image, and first-entry CRC corruption. All seven complete runtime traces
pass the independent closed policy; all 350 actual-trace mutations reject.
[Compressed runtime replay](replays/runtime-replay-summary.json) reproduces all
seven checks and the entire mutation receipt byte for byte. The
[runtime audit](linux/runtime-process-hostile-controls.json) binds inspected
archive bytes, provider/target, offsets and exact captured output. Historical
policy graphs remain isolated and unchanged. The measured hashlib operations
admit only fourteen ordered image-owned wake words and one empty `/dev/null`
character-device stream in its exact initialization phase.

Runtime execution uses a relocated read-only volume, uid/gid 65534, no network,
poisoned Python environment, inaccessible private temporary/home directories,
and no mounted repository, producer, input interpreter, headers or staging.
[Identity](linux/runtime-identity.txt) and [mounts](linux/runtime-mounts.txt)
record these conditions. A separate [preload trace](linux/preload.trace.txt.gz)
records the existing explicit `LD_PRELOAD` refusal with an actual old image;
this is not a general injection-resistance claim. The
[source status](linux/source-status.txt) is empty and
[source revision](linux/source-revision.txt) identifies the clean commit.

Mac packaging tests pass 541; Mac/GNU source Lua 5.4/5.5 suites pass 496/497.
All-target Clippy passes. Optimized GNU Python/probe, packaging and CLI suites
pass 160/63/23. Independent preparation/process/runtime/checker suites pass
20/23/5/11; all 253 historical policy units pass on both hosts. An initial GNU
Lua 5.5 invocation omitted the runner's matching feature; its retained failure
is explicitly excluded in [the source summary](checks/linux-source/summary.json).
The corrected invocation passes without source changes. The
[88-input GNU binding](checks/linux-source/source-commit-binding.json) and
[345 source/fixture bindings](checks/source-and-fixture-binding.json) identify
the exact reviewed inputs.

The two successful archives are byte-identical across builders, verified by
[the comparison](mac/archive-comparison.json): stripped 10,656 bytes,
SHA256 `7f51ef100404d171a32499fd0ce7d8ee9491320792727fc6071c1a8f429f7125`;
unstripped 10,651 bytes,
SHA256 `0e34e7535ec5358124feb9c0922ea4b2c1308c01b9ae2d3dbf53f2eacb2c6dce`.
The [seven small application archives](archives/) and
[inspected metadata](linux/archive-metadata.json) are retained. Large runtime
artifacts, libraries, launcher binaries and producer trees are omitted. Six
previous real-package traces also replay under their unchanged policy; receipts
are in [prior-corpus replays](checks/prior-corpus-replays/).

[SHA256SUMS](SHA256SUMS) binds every retained file except itself.
[Compressed content identities](compressed-content-identities.json) bind their
decoded bytes. Full runtime and preparation traces, reports, commands, statuses,
test logs and rejection receipts remain available beneath `linux/`, `mac/`,
`checks/` and `replays/`.

This is one pinned host metadata image on GNU Linux arm64. Selected stripped-tree
input requires stock sysconfig; it does not establish a genuine uv stripped
installation, uv's default catalog, version selection, bundled stripped startup,
arbitrary native packages or another platform. Backing input/output trees must
remain stable and disjoint, including unsupported descendant mount aliases.
Native lifecycle, wider package compatibility and four-platform release gates
remain open.
