# Product preparation of pinned host Python prerequisites (A7/A10)

Status: implementation contract, 13 October 2026.

Add `glue python-host` under the existing `python-pack` feature, also enabled by
`python-pbs`. It prepares the exact prerequisite trees for the two admitted
CPython 3.13.16 / PBS `20261009` host metadata profiles on GNU Linux arm64.
Provider selection and runtime/helper/loader identities remain unchanged.

```text
glue python-host --provider host-full --pbs-full FULL.tar.zst --output PREFIX [--json]
glue python-host --provider host-install --pbs-install-only INSTALL.tar.gz --output PREFIX [--json]
```

`PREFIX` must be an absolute canonical ASCII path satisfying the selected
profile's existing expanded-path and retained-descriptor budgets. Its parent
must already exist. These files can be prepared on a Unix builder, including
Mac, without executing the target interpreter. Non-Unix publication is explicitly
unsupported until permission/mtime semantics have evidence.

The full-source tree owns `lib/libpython3.13.so.1.0` and all 2,174 pinned sources
under `lib/python3.13/`: 2,175 files / 112,722,024 bytes. The install-only tree
owns the same library, all 1,037 pinned sources and the three exact stock encoding
caches: 1,041 files / 89,479,393 bytes. These fixed projections fit the existing
128 MiB selective-reader cap. They are embedding prerequisites rather than
complete general-purpose Python installations. No interpreter executable,
headers, symlinks, arbitrary native modules or installer is added. Report the
complete observed artifact inventory counts and regular payload bytes, plus
selected file identities and selected/omitted counts and bytes;
do not imply that unselected stock contents were installed.

Full preparation reuses the selective full inspector and metadata validation.
Install-only preparation adds a narrow independently pinned selective reader:
validate its complete compressed identity, single gzip stream and complete tar
inventory before returning selected regular payloads. It must not contain
`PYTHON.json`. Admission verifies the exact checked-in source/cache projections,
every selected size/hash and the existing library identity. The expected producer
and derived source/cache inventories are the already verified profile facts;
this operation does not claim a new full/install metadata-pair audit.

Expose an owned prerequisite constructor under the portable runtime `packaging`
facade and publish through `glue-pack`. Validate prefix, entire owned content map,
inventory and budgets before creating output. Create the new prefix exclusively;
existing files/directories/symlinks reject without changes. Write files with
exclusive creation, set source/cache/library mtime to the fixed stock epoch
`1704067200`, and set files to `0444` and directories to `0555`. These are explicit
publication transformations, not generic preservation of arbitrary tar metadata.
Write `provenance.json` last, then freeze the directory tree. Report exact owned
files, artifact identity, selected profile, transformations and provenance bytes.
Runtime execution remains unobserved. Keep the installation on immutable backing
storage during execution; read-only permissions alone do not freeze backing files.

Publication I/O failure returns an error and may leave a partial newly created
tree. Do not remove unrelated paths or claim atomic directory publication. Input
and parent trees must remain stable during the operation. Runtime verification
still checks the actual declared installation before acquiring Python; generation
does not replace or relax those checks.

Tests cover prefix/profile budgets, exact full/install source/cache projections,
library identities, corrupt/oversized/trailing inputs, deterministic output,
nonregular inputs, publication protection and permission/mtime transformations.
An independent file oracle verifies every emitted path/byte/mode/time on Mac and
GNU Linux. Preparation traces require one process and no child interpreter or
network activity. Replace the two historical host installer calls in the existing
three-provider native fixture, then replay its unchanged six-mode runtime policy
and compare archive identities to prior evidence. Retain complete traces,
provenance and independent checks without duplicating large payload trees in Git.

The existing install-only trace workload used a complete upstream installation.
Its stdlib-root enumeration contains 193 entries including dot entries. The
new declared source/cache projection has 191: `LICENSE.txt` and `lib-dynload`
are omitted along with other unselected stock content. Use an isolated strict
trace adapter that derives the 191 count from the exact checked-in source/cache
inventory and changes only the two metadata-host enumeration predicates for
this workload. The original policy files and their 193-entry expectation remain
unchanged. All archive, loader, startup, cache, descriptor, output, CRC and
no-extraction checks stay in force; extra/missing directory entries must reject.
The full-source projection already matches its existing 192-entry workload.

General installation/discovery, uv-tree ingestion, version selection, broader
package/native/platform compatibility and release gates remain separate work.
